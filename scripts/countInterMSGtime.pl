#!/usr/bin/perl
#
# Supponendo che le righe sono ordinate per numero
#di sessione TCP, fa la somma dei byte per tipo di MSG



#if($#ARGV!=1)
#{
#    printf("uso: countMSGbyte.pl <file> \n");
#    
#    exit(1);
#}

$filename=$ARGV[0];
#$param=$ARGV[1];


open(IN_file,$filename) or die ("can't open $filename\n");
$N=0;
$I=0;
#$M="MSG";
#$#B=5;
#@B=qw(0 0 0 0 0);
while (($line = <IN_file>)) {
        chomp ($line);
    if ($line !~ /#/)
    { 
        @data = split(' ', $line);
	
	if ($I==0)
	{
	if ($data[1] eq 'MSG_U' || $data[1] eq 'MSG_N')
	{
	$prevMSG =$data[1];
	$time_prevMSG = $data[10];
	$I=1;
	}
	}
	 else
	 {
	 if ($data[1] eq 'MSG_N' && $prevMSG eq 'MSG_U') # 
	 {
	 $time = $data[10] - $time_prevMSG;
	 print "Tempo digitazione: \t\t\t$time\n";
	 $prevMSG =$data[1];
	 $time_prevMSG = $data[10];
	 }
	 elsif ($data[1] eq 'MSG_U' && $prevMSG eq 'MSG_N') # 
	 {
	 $time = $data[10] - $time_prevMSG;
	 print "Tempo intermessaggio stesso utente: \t$time\n";
	 $prevMSG =$data[1];
	 $time_prevMSG = $data[10];
	 }
	 elsif ($data[1] eq 'MSG_?' && $prevMSG eq 'MSG_N')
	 {
	 $time = $data[10] - $time_prevMSG;
	 print "Tempo intermessaggio altro utente: \t$time\n";
	 $I=0;
	 }
	  
	 }
		
    }
		  
}

#print "$N @B\n";

 
