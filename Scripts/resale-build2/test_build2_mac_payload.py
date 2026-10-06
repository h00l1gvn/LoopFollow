"""Build2 copy-only permissions + stored payload regressions. No package/sign operation."""
import copy,hashlib,pathlib,stat,tempfile,unittest
import build2_contract as c
import mac_payload_permissions as m

class MacPayload(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=pathlib.Path(self.tmp.name);self.app=self.root/m.APP;self.app.mkdir(mode=0o700)
        for relative in sorted(m.EXECUTABLES|{'Contents/Info.plist','Contents/Resources/Build2NewResource.dat'}):
            p=self.app/relative;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(('SYNTHETIC '+relative).encode());p.chmod(0o700 if relative in m.EXECUTABLES else 0o600)
        for p in self.app.rglob('*'):
            if p.is_dir():p.chmod(0o700)
        rows=[{'bundle_id':id,'signature_verified':True,'profile_verified':True,'certificate_sha256':c.CERT_SHA,'version':'0.1.0','build':'2'} for id in [c.BASE+'.mac',c.BASE+'.mac.widgets']]
        self.repair=c.source_payload_scope(m.tree_snapshot(self.app),rows)
    def rows(self):
        r={'.':{'kind':'directory','mode':0o755,'uid':0,'gid':0},m.APP:{'kind':'directory','mode':0o755,'uid':0,'gid':0}}
        for k in self.repair['source_directories']:
            if k!='.':r[m.APP+'/'+k]={'kind':'directory','mode':0o755,'uid':0,'gid':0}
        for k,h in self.repair['source_file_sha256'].items():r[m.APP+'/'+k]={'kind':'file','mode':0o755 if k in m.EXECUTABLES else 0o644,'uid':0,'gid':0,'sha256':h}
        return r
    def reject(self,fn,*args):
        with self.assertRaises(m.validation.ValidationError):fn(*args)
    def test_new_resource_members_stage_without_build1_hardcoded_counts(self):
        before=m.tree_snapshot(self.app);staged,source,copy_=m.stage_copy(self.app,self.root/'private-stage',self.repair)
        self.assertEqual(m.tree_snapshot(self.app),before);self.assertEqual(source,before);self.assertEqual(len(self.repair['source_file_sha256']),4)
        for path,row in copy_.items():self.assertEqual(row['mode'],0o755 if row['kind']=='directory' or path in m.EXECUTABLES else 0o644)
        self.assertEqual((self.root/'private-stage').stat().st_mode&0o777,0o700)
        self.assertTrue(all(row['sha256']==source[k]['sha256'] for k,row in copy_.items() if row['kind']=='file'))
    def test_stored_root_only_permissions_rejected_even_if_hashes_match(self):
        rows=self.rows();rows[m.APP+'/Contents/Info.plist']['mode']=0o600;self.reject(m.check_cpio,rows,self.repair)
        rows=self.rows();rows[m.APP]['mode']=0o700;self.reject(m.check_cpio,rows,self.repair)
    def test_expected_directory_and_file_types_are_required(self):
        rows=self.rows();rows[m.APP]['kind']='file';self.reject(m.check_cpio,rows,self.repair)
        rows=self.rows();rows[m.APP+'/Contents/Info.plist']['kind']='directory';self.reject(m.check_cpio,rows,self.repair)
    def test_root_ownership_extra_write_member_hash_and_executable_gates(self):
        key=m.APP+'/Contents/Info.plist'
        for field,value in [('uid',1),('gid',1),('mode',0o664),('mode',0o755),('sha256','0'*64)]:
            rows=self.rows();rows[key][field]=value;self.reject(m.check_cpio,rows,self.repair)
        rows=self.rows();rows[m.APP+'/Other.dat']={'kind':'file','mode':0o644,'uid':0,'gid':0,'sha256':'0'*64};self.reject(m.check_cpio,rows,self.repair)
    def test_actual_stored_modes_and_bom_must_agree(self):
        rows=self.rows();self.assertTrue(m.check_cpio(rows,self.repair)['world_read_traverse_verified'])
        def bom(rows):return ('\n'.join(k+'\t'+format((stat.S_IFDIR if r['kind']=='directory' else stat.S_IFREG)|r['mode'],'o')+'\t'+str(r['uid'])+'\t'+str(r['gid']) for k,r in rows.items())+'\n').encode()
        m.check_bom(bom(rows),rows)
        wrong=copy.deepcopy(rows);wrong[m.APP+'/Contents/Info.plist']['mode']=0o600;self.reject(m.check_bom,bom(wrong),rows)
    def test_original_modes_bytes_and_extra_symlink_not_normalized(self):
        (self.app/'Contents/Info.plist').write_bytes(b'CHANGED');self.reject(m.stage_copy,self.app,self.root/'stage',self.repair)
        (self.app/'Contents/link').symlink_to(self.app/'Contents/Info.plist');self.reject(m.tree_snapshot,self.app)

if __name__=='__main__':unittest.main()
