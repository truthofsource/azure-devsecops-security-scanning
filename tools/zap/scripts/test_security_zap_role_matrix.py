import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zap_role_matrix as z

ADMIN = 'a' * 8 + '-aaaa-aaaa-aaaa-' + 'a' * 12
CAREGIVER = 'b' * 8 + '-bbbb-bbbb-bbbb-' + 'b' * 12


class MatrixTests(unittest.TestCase):
    def probe(self, path, token):
        if path == '/api/health':return 200, '{}'
        if token is None:return 401, '{}'
        if path == '/api/me':
            return 200, json.dumps({'objectId': ADMIN if token == 'admin' else CAREGIVER,
                                    'roles': ['Workforce.Admin' if token == 'admin' else 'Workforce.Caregiver'],
                                    'name': 'PRIVATE_CANARY'})
        return (400 if path == z.SETTINGS else 503, '{}') if token == 'admin' else (403, '{}')

    def test_exact_synthetic_matrix_and_no_private_response_in_summary(self):
        calls=[]
        def probe(path, token):
            calls.append((path, token));return self.probe(path, token)
        result=z.evaluate(probe, 'admin', 'caregiver', ADMIN, CAREGIVER)
        self.assertEqual(len(calls),10)
        self.assertEqual({x[0] for x in calls},z.ALLOWED)
        self.assertNotIn('PRIVATE_CANARY',json.dumps(result))

    def test_wrong_caregiver_account_stops_before_protected_routes(self):
        calls=[]
        def probe(path, token):
            calls.append(path)
            if token=='caregiver':return 200,json.dumps({'objectId':CAREGIVER,'roles':['Workforce.Caregiver','Workforce.Admin']})
            return self.probe(path,token)
        with self.assertRaises(RuntimeError):z.evaluate(probe,'admin','caregiver',ADMIN,CAREGIVER)
        self.assertNotIn(z.SETTINGS,calls)

    def test_changed_status_and_wrong_identity_are_not_clean_acceptance(self):
        with self.assertRaisesRegex(RuntimeError,'anonymous /api/me expected 401, received 200') as error:
            z.evaluate(lambda path,token:(200,'{}'),'admin','caregiver',ADMIN,CAREGIVER)
        self.assertNotIn('PRIVATE_CANARY',str(error.exception))
        with self.assertRaises(ValueError):z.evaluate(self.probe,'same','same',ADMIN,CAREGIVER)

    def test_malformed_role_claim_shape_stops_before_protected_reads(self):
        def probe(path,token):
            if token=='admin':return 200,json.dumps({'objectId':ADMIN,'roles':'Workforce.Admin'})
            return self.probe(path,token)
        with self.assertRaisesRegex(RuntimeError,'role array'):
            z.evaluate(probe,'admin','caregiver',ADMIN,CAREGIVER)

    def test_arbitrary_routes_redirect_hosts_and_header_injection_fail(self):
        for route in ('https://example.org/api/me','/api/me\r\nX-Test: true','/api/workflownotifications/settings','/api/provider/sync'):
            with self.subTest(route=route),self.assertRaises(ValueError):z.request_text(route)
        with self.assertRaises(ValueError):z.request_text('/api/me','x'*60+'\r\nX-Test: true')
        self.assertTrue(z.request_text('/api/me','x'*60).startswith('GET '+z.API+'/api/me '))

    def test_missing_private_tokens_start_no_container(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(z.subprocess,'run') as docker:
            with self.assertRaises(ValueError):z.run(Path(folder)/'missing',Path(folder)/'also-missing',ADMIN,CAREGIVER,Path(folder)/'out.json','docker')
            docker.assert_not_called()


if __name__=='__main__':unittest.main()
