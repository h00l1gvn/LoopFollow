import unittest
from pathlib import Path
from unittest.mock import patch
import diagnose_three_push_profiles as d
from test_three_push_profiles import Fake,SCOPE,CERT
class ReadOnly(unittest.TestCase):
 def test_workflow_uses_existing_envelope_scope(self):
  root=Path(__file__).resolve().parents[2]
  workflow=(root/'.github/workflows/resale-build2-three-profile-diagnostic.yml').read_text()
  scope=root/'Scripts/resale-build2/three-push-profile-envelope-scope.json'
  self.assertTrue(scope.is_file())
  self.assertIn(scope.relative_to(root).as_posix(),workflow)
 def test_exact_collection_profile_read_without_unapproved_single_resource_or_posts(self):
  f=Fake(True)
  with patch.object(d.a,'certificate',return_value=CERT),patch.object(d.api,'decode_profile',side_effect=f.decode):v=d.run(f,SCOPE)
  self.assertEqual(len(v['targets']),3);self.assertEqual(v['account_mutations'],0);self.assertEqual(f.post_calls,[]);self.assertTrue(all(x['evidence']['reusable_for_build2'] for x in v['targets']))
 def test_metadata_single_profile_route_is_refused_before_network(self):
  from urllib.parse import urlparse
  with self.assertRaises(d.api.AuditError):d.api.validate_metadata_path('https://api.appstoreconnect.apple.com',urlparse('https://api.appstoreconnect.apple.com/v1/profiles/SYNTHETIC'))
if __name__=='__main__':unittest.main()
