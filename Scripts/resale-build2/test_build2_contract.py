"""Meaningful offline release guards; no provider, GitHub, keychain or signing calls."""
import copy,hashlib,json,pathlib,plistlib,tempfile,unittest
import build2_contract as c

class Guards(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=pathlib.Path(self.temp.name);self.rows=[]
        def write(path,value):
            p=self.root/path;p.parent.mkdir(parents=True,exist_ok=True);raw=plistlib.dumps(value) if isinstance(value,dict) else value;p.write_bytes(raw);self.rows.append({'path':path,'sha256':c.sha(raw)})
        icon='apple/AssetsSource/final-approved-icon.png';write(icon,b'SYNTHETIC APPROVED ARTWORK FIXTURE')
        for target,identifier in c.TARGETS.items():
            write(f'apple/Configuration/{target}.plist',{'CFBundleShortVersionString':'0.1.0','CFBundleVersion':'2','CFBundleDisplayName':'Re$Burrow'})
            ent={'com.apple.security.application-groups':[c.GROUP]}
            if identifier in c.PUSH:ent[c.PUSH[identifier]]='production'
            write(f'apple/Configuration/{target}.entitlements',ent)
        self.manifest={'files':self.rows,'product_photos':0,'credentials_profiles_databases_logs_or_workspace_history':False}
        self.review={'root_release_reviewed':True,'selected_icon_owner_approved':True,'interim_artwork_rejected':True,'source_sha':'a'*40,'version':'0.1.0','build':'2','team':c.TEAM,'group':c.GROUP,'approved_icon_asset_path':icon,'approved_icon_sha256':self.rows[0]['sha256']}
    def rejects(self,fn,*args):
        with self.assertRaises(c.GateError):fn(*args)
    def test_exact_new_freeze_passes_without_dispatch(self):self.assertFalse(c.validate_freeze(self.review,self.manifest,self.root)['release_dispatched'])
    def test_interim_icon_cannot_freeze(self):
        for key in ['root_release_reviewed','selected_icon_owner_approved','interim_artwork_rejected']:
            review={**self.review,key:False};self.rejects(c.validate_freeze,review,self.manifest,self.root)
    def test_old_source_and_wrong_build_cannot_release(self):
        for key,value in [('source_sha',c.OLD_SOURCE),('source_sha','main'),('build','1'),('group','group.other'),('team','OTHER')]:self.rejects(c.validate_freeze,{**self.review,key:value},self.manifest,self.root)
    def test_selected_icon_and_source_mutation_rejected(self):
        self.rejects(c.validate_freeze,{**self.review,'approved_icon_sha256':'0'*64},self.manifest,self.root)
        (self.root/self.review['approved_icon_asset_path']).write_bytes(b'REJECTED DIFFERENT ICON');self.rejects(c.validate_freeze,self.review,self.manifest,self.root)
    def test_private_payload_duplicates_and_traversal_rejected(self):
        for path in ['../private.p8','apple/runtime/secrets.json','apple/key.p8','apple/photo.jpg']:
            changed=copy.deepcopy(self.manifest);changed['files'].append({'path':path,'sha256':'0'*64});self.rejects(c.validate_freeze,self.review,changed,self.root)
        changed=copy.deepcopy(self.manifest);changed['files'].append(changed['files'][0]);self.rejects(c.validate_freeze,self.review,changed,self.root)
        self.rejects(c.validate_freeze,self.review,{**self.manifest,'product_photos':1},self.root)
    def test_three_receiving_production_grants_required(self):
        for bundle,key in c.PUSH.items():
            self.assertTrue(c.require_push_grants(bundle,{key:'production'},{key:'production'})['production_push_verified'])
            self.rejects(c.require_push_grants,bundle,{key:'production'},{key:'development'})
            self.rejects(c.require_push_grants,bundle,{key:'production'},{})
            self.rejects(c.require_push_grants,bundle,{},{key:'production'})
    def test_widgets_and_tv_must_not_acquire_unrelated_push(self):
        for bundle in set(c.TARGETS.values())-set(c.PUSH):
            self.assertFalse(c.require_push_grants(bundle,{}, {})['production_push_verified']);self.rejects(c.require_push_grants,bundle,{'aps-environment':'production'}, {})
    def mac(self):
        data={'.':{'kind':'directory','mode':0o700},'Contents':{'kind':'directory','mode':0o700}}
        for path in ['Contents/MacOS/ResaleBurrowMac','Contents/PlugIns/ResaleBurrowMacWidgets.appex/Contents/MacOS/ResaleBurrowMacWidgets','Contents/Info.plist']:
            data[path]={'kind':'file','mode':0o700 if '/MacOS/' in path else 0o600,'sha256':c.sha(path.encode())}
        rows=[{'bundle_id':id,'signature_verified':True,'profile_verified':True,'certificate_sha256':c.CERT_SHA,'version':'0.1.0','build':'2'} for id in [c.BASE+'.mac',c.BASE+'.mac.widgets']]
        return data,rows
    def test_fresh_validated_mac_inventory_not_hardcoded_to_build1_members(self):
        data,rows=self.mac();self.assertEqual(len(c.source_payload_scope(data,rows)['source_file_sha256']),3)
        data['Contents/new-build2-resource.dat']={'kind':'file','mode':0o600,'sha256':'c'*64};self.assertEqual(len(c.source_payload_scope(data,rows)['source_file_sha256']),4)
    def test_mac_source_validation_and_unexpected_executable_fail_closed(self):
        data,rows=self.mac();rows[0]['signature_verified']=False;self.rejects(c.source_payload_scope,data,rows)
        data,rows=self.mac();rows[0]['certificate_sha256']='0'*64;self.rejects(c.source_payload_scope,data,rows)
        data,rows=self.mac();data['Contents/Info.plist']['mode']=0o700;self.rejects(c.source_payload_scope,data,rows)
        data,rows=self.mac();data['Contents/Info.plist']['kind']='symlink';self.rejects(c.source_payload_scope,data,rows)
        data,rows=self.mac();data['Contents/Info.plist']['sha256']='not-hash';self.rejects(c.source_payload_scope,data,rows)
        data,rows=self.mac();data['Contents/Info.plist']['mode']=0o4600;self.rejects(c.source_payload_scope,data,rows)

if __name__=='__main__':unittest.main()
