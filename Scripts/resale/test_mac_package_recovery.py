import base64, copy, hashlib, importlib.util, io, json, os, pathlib, tarfile, tempfile, unittest
from unittest.mock import patch
import package_resale_mac_archive as package
import restore_resale_installer_only as restore
import validate_resale_export as validation

class GuardTests(unittest.TestCase):
    def test_component_only_command_no_build_or_upload(self):
        name='3rd Party Mac Developer Installer: Fixture (N8K8G6QA36)'
        command=package.component_command('/private/app.app','/private/ephemeral.keychain-db','/private/one.pkg',name)
        self.assertEqual(command,['/usr/bin/productbuild','--sign',name,'--keychain','/private/ephemeral.keychain-db','--component','/private/app.app','/Applications','/private/one.pkg'])
    def test_wrong_common_name_team_or_developer_id_rejected(self):
        for name in ['Developer ID Installer: Fixture (N8K8G6QA36)','3rd Party Mac Developer Installer: Fixture (OTHERTEAM)','']:
            with self.subTest(name=name),self.assertRaises(validation.ValidationError):package.component_command('app','chain','pkg',name)
    def test_toc_pins_leaf_not_intermediate(self):
        leaf=b'actual-leaf';other=b'intermediate'
        raw=('<xar><toc><signature style="RSA"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>'+base64.b64encode(leaf).decode()+'</X509Certificate><X509Certificate>'+base64.b64encode(other).decode()+'</X509Certificate></X509Data></KeyInfo></signature></toc></xar>').encode()
        self.assertEqual(package.installer_leaf_from_toc(raw),hashlib.sha256(leaf).hexdigest())
    def test_toc_missing_duplicate_or_entity_rejected(self):
        for raw in [b'<xar/>',b'<xar><signature/><signature/></xar>',b'<!DOCTYPE x><xar/>',b'<xar><signature><X509Certificate>notbase64!</X509Certificate></signature></xar>']:
            with self.subTest(raw=raw),self.assertRaises(validation.ValidationError):package.installer_leaf_from_toc(raw)
    def tar(self,path,name,kind=None):
        with tarfile.open(path,'w:gz') as t:
            row=tarfile.TarInfo(name)
            if kind:row.type=kind;row.linkname='/outside';t.addfile(row)
            else:row.size=1;t.addfile(row,io.BytesIO(b'x'))
    def test_archive_wrong_hash_rejected_before_extract(self):
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d);self.tar(p/'x.tar.gz','ResaleBurrow.xcarchive/Info.plist')
            with self.assertRaises(validation.ValidationError):package.extract_archive(p/'x.tar.gz',p/'output')
            self.assertFalse((p/'output').exists())
    def test_traversal_symlink_hardlink_outside_scope_rejected(self):
        for name,kind in [('ResaleBurrow.xcarchive/../../escape',None),('/absolute',None),('other/Info.plist',None),('ResaleBurrow.xcarchive/link',tarfile.SYMTYPE),('ResaleBurrow.xcarchive/hard',tarfile.LNKTYPE)]:
            with self.subTest(name=name),tempfile.TemporaryDirectory() as d:
                p=pathlib.Path(d);self.tar(p/'x.tar.gz',name,kind)
                with patch.object(package,'ARCHIVE_SHA',validation.digest(p/'x.tar.gz')),self.assertRaises(validation.ValidationError):package.extract_archive(p/'x.tar.gz',p/'output')
                self.assertFalse((p/'output').exists())
    def test_duplicate_member_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d)
            with tarfile.open(p/'x.tar.gz','w:gz') as t:
                for _ in range(2):row=tarfile.TarInfo('ResaleBurrow.xcarchive/Info.plist');row.size=1;t.addfile(row,io.BytesIO(b'x'))
            with patch.object(package,'ARCHIVE_SHA',validation.digest(p/'x.tar.gz')),self.assertRaises(validation.ValidationError):package.extract_archive(p/'x.tar.gz',p/'output')
    def test_local_packaging_blocked_before_commands(self):
        with patch.dict(os.environ,{'GITHUB_ACTIONS':'false'}),self.assertRaises(validation.ValidationError):package.package({},'missing',{},'missing','missing','missing')
    def test_only_installer_blob_paths(self):
        self.assertEqual(restore.PATHS,{'certs/mac_installer_distribution/WBR8H2GCGZ.cer','certs/mac_installer_distribution/WBR8H2GCGZ.p12'})
        source=pathlib.Path(restore.__file__).read_text()
        self.assertNotIn("request('POST'",source);self.assertNotIn("request('DELETE'",source)
    def test_get_only_store_blocks_writes_before_transport(self):
        client=object.__new__(restore.InstallerStoreGetOnly)
        for method in ['POST','PATCH','PUT','DELETE']:
            with self.subTest(method=method),self.assertRaises(Exception):client.request(method,'/anything',{})
    def test_restore_does_not_fetch_unrelated_blobs(self):
        class Client:
            def __init__(self):self.paths=[]
            def request(self,method,path):
                self.paths.append((method,path))
                if '/commits/' in path:return {'sha':restore.MATCH,'tree':{'sha':'a'*40}}
                return {'truncated':False,'tree':[{'path':'unrelated/profile.mobileprovision','sha':'b'*40,'type':'blob','mode':'100644'}]}
        client=Client()
        with patch.object(restore.profiles,'validate_scope'),patch.object(restore.profiles,'verified_certificate'),self.assertRaises(Exception):restore.restore(client,None,{'match_material_commit':restore.MATCH},'never', 'private','private')
        self.assertEqual(len(client.paths),2);self.assertTrue(all(method=='GET' for method,_ in client.paths))
    def test_no_archive_or_resigning_invocation_in_driver(self):
        source=pathlib.Path(package.__file__).read_text()
        self.assertNotIn("'-exportArchive'",source);self.assertNotIn("'archive',cwd",source);self.assertNotIn("'codesign','--sign'",source)
    def test_valid_transport_exact_input_no_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d);self.tar(p/'x.tar.gz','ResaleBurrow.xcarchive/Info.plist')
            with patch.object(package,'ARCHIVE_SHA',validation.digest(p/'x.tar.gz')):
                archive=package.extract_archive(p/'x.tar.gz',p/'output');self.assertEqual((archive/'Info.plist').read_bytes(),b'x')
                with self.assertRaises(validation.ValidationError):package.extract_archive(p/'x.tar.gz',p/'output')
if __name__=='__main__':unittest.main()
