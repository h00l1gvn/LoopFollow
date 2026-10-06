import base64,hashlib,json,tempfile,unittest
from pathlib import Path
import resale_scoped_profiles as profiles
import store_resale_profiles as store
import resale_apple_audit as audit
SCOPE=json.loads(Path(__file__).with_name('signing-export-scope.json').read_text())
HEAD='a'*40;TREE='b'*40;NEW_TREE='c'*40;NEW_COMMIT='d'*40
class Client:
    def __init__(self,existing=None,changed=False):self.calls=[];self.existing=existing or {};self.changed=changed;self.refs=0
    def request(self,method,path,body=None):
        self.calls.append((method,path,body))
        if path==store.PREFIX:return {'private':True}
        if method=='GET' and path.endswith('/git/ref/heads/master'):
            self.refs+=1
            return {'object':{'sha':NEW_COMMIT if any(m=='PATCH' for m,_,_ in self.calls) else ('e'*40 if self.changed else HEAD)}}
        if '/git/commits/' in path:return {'sha':HEAD,'tree':{'sha':TREE}}
        if method=='GET' and '/git/trees/' in path:
            rows=[{'path':p,'mode':'100644','type':'blob','sha':sha} for p,(sha,_) in self.existing.items()]
            if NEW_TREE in path:
                additions=next(body['tree'] for method,p,body in self.calls if method=='POST' and p.endswith('/git/trees'))
                for row in additions:
                    raw=row['content'].encode();rows.append({'path':row['path'],'mode':'100644','type':'blob','sha':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()})
            return {'tree':rows}
        if '/git/blobs/' in path:
            raw=next(raw for sha,raw in self.existing.values() if path.endswith(sha));return {'encoding':'base64','content':base64.b64encode(raw).decode()}
        if method=='POST' and path.endswith('/git/trees'):return {'sha':NEW_TREE}
        if method=='POST' and path.endswith('/git/commits'):return {'sha':NEW_COMMIT}
        if method=='PATCH' and path.endswith('/git/refs/heads/master'):return {'object':{'sha':NEW_COMMIT}}
        raise AssertionError('Unexpected route')
def fixture(root):
    rows=[]
    for i,t in enumerate(SCOPE['targets']):
        raw=('synthetic signed profile '+str(i)).encode();encrypted=profiles.encrypt_profile(raw,'synthetic-only');path=profiles.profile_path(t);dest=root/path;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(encrypted)
        rows.append({'bundle_id':t['bundle_id'],'target':t['target'],'path':path,'verified':True,'native_readback_verified':True,'native_profile_id':t['target'],'profile_type':t['profile_type'],'certificate_sha256':profiles.CERT_SHA,'sha256':hashlib.sha256(raw).hexdigest(),'encrypted_sha256':hashlib.sha256(encrypted).hexdigest()})
    return {'complete':True,'profile_count':7,'team':profiles.TEAM,'group':profiles.GROUP,'source_sha':SCOPE['source_sha'],'profiles':rows}
class Guards(unittest.TestCase):
    def test_exact_seven_additions_inherit_tree_and_nonforce_cas(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);manifest=fixture(root);client=Client();result=store.store_profiles(client,SCOPE,manifest,root,HEAD,'synthetic-only')
        writes=[r for r in client.calls if r[0]!='GET'];self.assertEqual([r[0] for r in writes],['POST','POST','PATCH'])
        body=writes[0][2];self.assertEqual(body['base_tree'],TREE);self.assertEqual({r['path'] for r in body['tree']},{profiles.profile_path(t) for t in SCOPE['targets']})
        self.assertTrue(all(r['mode']=='100644' and r['type']=='blob' and base64.b64decode(r['content']).startswith(b'match_encrypted_v2__') for r in body['tree']))
        self.assertEqual(writes[-1][2],{'sha':NEW_COMMIT,'force':False});self.assertEqual(result['match_commit'],NEW_COMMIT)
    def test_identical_existing_profiles_replay_without_any_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);manifest=fixture(root);existing={r['path']:((str(i+1)*40)[:40],(root/r['path']).read_bytes()) for i,r in enumerate(manifest['profiles'])};client=Client(existing);result=store.store_profiles(client,SCOPE,manifest,root,HEAD,'synthetic-only')
        self.assertTrue(result['replayed']);self.assertFalse(any(m!='GET' for m,_,_ in client.calls))
    def test_stale_head_changed_profile_and_changed_bytes_never_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);manifest=fixture(root);client=Client(changed=True)
            with self.assertRaises(audit.AuditError):store.store_profiles(client,SCOPE,manifest,root,HEAD,'synthetic-only')
            self.assertFalse(any(m!='GET' for m,_,_ in client.calls))
            r=manifest['profiles'][0];client=Client({r['path']:('1'*40,profiles.encrypt_profile(b'different','synthetic-only'))})
            with self.assertRaises(audit.AuditError):store.store_profiles(client,SCOPE,manifest,root,HEAD,'synthetic-only')
            self.assertFalse(any(m!='GET' for m,_,_ in client.calls))
            (root/r['path']).write_bytes(b'tampered')
            with self.assertRaises(audit.AuditError):store.validate_manifest(SCOPE,manifest,root)
    def test_route_never_allows_cert_creation_delete_other_repo_or_branch(self):
        client=store.StoreClient('synthetic')
        for method,path in [('DELETE',store.PREFIX+'/git/refs/heads/master'),('POST','https://api.appstoreconnect.apple.com/v1/certificates'),('PATCH',store.PREFIX+'/git/refs/heads/main'),('POST','/repos/other/repo/git/trees')]:
            with self.assertRaises(audit.AuditError):client.request(method,path,{})
if __name__=='__main__':unittest.main()
