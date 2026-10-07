"""Actual material/export entry boundaries: no iOS work or credentials allowed."""
import unittest
from unittest.mock import patch
import build2_contract as c
import restore_build2_material as r
import export_build2_family as e
class PlatformBoundary(unittest.TestCase):
 def test_restore_rejects_ios_before_scope_credentials_or_network(self):
  class Forbidden:
   def __getattr__(self,name):raise AssertionError("Credential or network access attempted")
  with self.assertRaisesRegex(c.GateError,"mac_tv_material_only"):
   r.restore(Forbidden(),Forbidden(),{},"ios","/not-created",Forbidden(),Forbidden())
 def test_export_rejects_ios_before_runner_or_material(self):
  with self.assertRaisesRegex(c.GateError,"mac_tv_export_only"):
   e.plan({}, {}, "ios", "/not-read", "/not-read", "/not-created")
 def test_export_has_exact_two_destinations(self):
  self.assertEqual(set(e.DESTINATIONS),{"macos","tvos"})
if __name__=="__main__":unittest.main()
