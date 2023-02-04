use CGI;

my $q = CGI->new;

my $lightweight_fh  = $q->upload('file1');
my $filename = $q->param('file1');

my $dir = 'uploads/';

my $msg;

mkdir($dir) unless (-d $dir);

# undef may be returned if it's not a valid file handle
if (defined $lightweight_fh) {
	# Upgrade the handle to one compatible with IO::Handle:
	my $io_handle = $lightweight_fh->handle;

	open (OUTFILE,'>', $dir . $filename);
	while ($bytesread = $io_handle->read($buffer,1024)) {
		print OUTFILE $buffer;
	}
	$msg = 'The file \'' . $filename . '\' was uploaded successfully with perl';
}
else {
	$msg = 'No file was uploaded';
}

print '<html><body><p>' . $msg . '</p></body></html>';