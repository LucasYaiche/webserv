import cgi, os

form = cgi.FieldStorage()

username = form.getvalue('username')
password = form.getvalue('password')

print("""\
<html><body>
<h1>Welcome %s</h1>
</body></html>
""" % (username, ))