
#!/usr/bin/python

# import os

# a = os.getenv('AUTH_TYPE')

# print "Content-type:text/html\r\n\r\n"
# print '<html>'
# print '<head>'
# print '<title>Hello World - First CGI Program</title>'
# print '</head>'
# print '<body>'
# print '<h2>Hello World! This'
# print a
# print 'is my first CGI program</h2>'
# print '</body>'
# print '</html>'

import cgi, os

form = cgi.FieldStorage()

fileitem = form['file1']

path = "./uploads/"

isExist = os.path.exists(path)

if not isExist:
	os.makedirs(path)

if fileitem.filename:
	fn = os.path.basename(fileitem.filename)
	open(path + fn, 'wb').write(fileitem.file.read())
	message = "The file '" + fn + "' was uploaded successfully with python"

else:
	message = "No file was uploaded"

print ("""\
<html><body>
<p>%s</p>
</body></html>
""" % (message, ))