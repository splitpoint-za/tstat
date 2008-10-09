#! /usr/bin/perl

print ".
.
.	
.	Edit HOWTO.pod 
.
.	Info about pod `man perlpod`
.
.	Export to html, man, txt, ansi, latex
.		./README.pl -c
.
.       Export and compile latex to ps, pdf
.	        ./README.pl
.
";

foreach $pod (glob("*pod")) { 
    ( $file = $pod ) =~ s/.pod//g;
    
    print "Exporting ansi (colored text)\n";
    system("pod2text  -c -i 8 -l  $pod > $file.ansi");

    print "Exporting plain text\n";
    system("pod2text     -i 8 -l  $pod > $file.txt");
    
    print "Exporting manpage\n";
    system("pod2man  --section='1' --release='1.x' --center='Tstat Documentation' --name='TSTAT-HOWTO-$file'  $pod > $file.man");   

    print "Exporting html\n";
    # --noindex
    system("pod2html --infile=$pod --outfile=$file.html --norecurse");   

    print "Exporting latex\n";
    $preamble = '
    \documentclass[11pt]{article}
    \usepackage{a4wide}
    \usepackage[dvips]{graphicx}
    \newcommand{\printindex}[0]{} %recover pod2latex bug
    \begin{document}
    \begin{center}
        \includegraphics[width=\textwidth]{tstat_banner.eps}
    \end{center}
    \tableofcontents
    ';
    system("pod2latex --preamble '$preamble' --full $pod -out temp.tex");   

    print "Customizing latex\n";
    open TMP, "temp.tex";
    open OUT, "> $file.tex";
    while(<TMP>) {
	 chomp;
	 next if (m/^\s*$/ and $skip);
	 $skip = 0;
	 
   	 s/subsection\*/subsection/;
	 s/\\begin\{verbatim\}/\\begin{small}\\begin{verbatim}/;
	 s/\\end\{verbatim\}/\\end{verbatim}\\end{small} \\noindent/
	 	and $skip=1;
	 s/\\S\\ref/Sec.~\\ref/;
	 print OUT "$_\n";
    }
    close TMP;
    close OUT;
    unlink "temp.tex";

    exit if( $ARGV[0] eq '-c' );

    print "Compiling latex\n";
     system("[ -d tex ] || mkdir tex; 
            cd tex; 
	    cp -f ../$file.tex .
	    latex $file && > /dev/null 2> /dev/null
	    latex $file > LOG.latex 2>&1
	    dvipdf $file 
	    dvips $file -o $file.ps 
	    cp -f *.{ps,pdf} .. ");
}
print ".	
.	Fresh files:
.
";
system("ls -lrt $file*"); 

