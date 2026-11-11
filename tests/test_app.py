import os
import re
import tempfile
import unittest
from app import create_app


class AppTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.app=create_app({'TESTING':True,'SECRET_KEY':'test-key-'*8,'DATABASE':os.path.join(self.tmp.name,'test.db')})
        runner=self.app.test_cli_runner()
        for email in ['one@example.com','two@example.com']:
            result=runner.invoke(args=['create-user','--email',email,'--name','Profissional','--password','long-test-password'])
            self.assertEqual(result.exit_code,0,result.output)
        self.client=self.app.test_client()
        self.login('one@example.com')

    def tearDown(self):
        self.tmp.cleanup()

    def post(self,path,data=None,client=None):
        client=client or self.client
        client.get('/login')
        with client.session_transaction() as s: token=s['csrf']
        return client.post(path,data={**(data or {}),'csrf':token},follow_redirects=True)

    def login(self,email,client=None):
        return self.post('/login',{'email':email,'password':'long-test-password'},client)

    def patient(self,name='Maria'):
        return self.post('/pacientes',{'name':name,'phone':'11999999999'})

    def book(self,**kwargs):
        return self.post('/agenda',{'patient':'1','start':'2026-11-12T10:00','duration':'50','amount':'180.50','mode':'Online',**kwargs})

    def test_workflow_and_conflict(self):
        self.patient()
        self.assertIn('Sessão agendada',self.book().text)
        self.assertIn('Já existe',self.book(start='2026-11-12T10:30').text)
        self.assertIn('Sessão agendada',self.book(start='2026-11-12T10:50').text)
        self.post('/sessoes/1/atualizar',{'action':'paid'})
        text=self.client.get('/financeiro?month=2026-11').text
        self.assertIn('Pago · Estornar',text)
        self.assertIn('R$ 180,50',text)
        self.assertIn('Estorne',self.post('/sessoes/1/atualizar',{'action':'Cancelada'}).text)
        self.post('/sessoes/1/atualizar',{'action':'paid'})
        self.post('/sessoes/1/atualizar',{'action':'Cancelada'})
        self.assertIn('Sessão agendada',self.book().text)
        self.assertIn('wa.me/5511999999999',self.client.get('/lembrete/3').location)
        self.assertEqual(self.client.get('/').status_code,200)

    def test_isolation(self):
        self.patient(); self.book()
        other=self.app.test_client(); self.login('two@example.com',other)
        self.assertNotIn('Maria',other.get('/pacientes').text)
        self.assertEqual(self.post('/sessoes/1/atualizar',{'action':'paid'},other).status_code,404)
        self.assertEqual(other.get('/lembrete/1').status_code,404)
        self.assertNotIn('Maria',other.get('/financeiro/exportar').text)
        self.assertIn('Confira',self.post('/agenda',{'patient':'1'},other).text)

    def test_validation_and_security(self):
        self.assertEqual(self.client.post('/pacientes',data={'name':'unsafe'}).status_code,400)
        self.patient('<script>alert(1)</script>')
        self.assertNotIn('<script>',self.client.get('/pacientes').text)
        for amount in ['NaN','Infinity','-1','1.001']:
            self.assertIn('Confira',self.book(amount=amount).text)
        self.book()
        self.assertIn("default-src 'self'",self.client.get('/').headers['Content-Security-Policy'])
        self.post('/logout')
        self.assertEqual(self.client.get('/').status_code,302)

    def test_rate_limit_and_csv(self):
        self.patient('=HYPERLINK("bad")'); self.book()
        self.assertIn("'=HYPERLINK",self.client.get('/financeiro/exportar').text)
        self.post('/logout')
        for _ in range(5):
            self.assertEqual(self.post('/login',{'email':'one@example.com','password':'bad'}).status_code,401)
        self.assertEqual(self.login('one@example.com').status_code,429)

    def test_waitlist(self):
        self.patient()
        self.assertIn('Na espera',self.post('/pacientes/1/espera').text)
        self.book()
        self.assertNotIn('Na espera',self.client.get('/pacientes').text)


if __name__=='__main__': unittest.main()
