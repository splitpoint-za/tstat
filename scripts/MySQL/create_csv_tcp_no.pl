#!/usr/bin/perl -w

use Text::CSV;
use IO::File;
use Socket;
use strict;

require 'check_internal.pl';

# substitute here the CSV filename, that must be the same than the
# corresponding MySQL table

my $fh_csv = new IO::File ">tcp_no.csv";


{
 my $line;
 my @csv_line;
 my $csv_obj;
 $csv_obj = new Text::CSV->new({eol => "\n"});

 while($line = <>)
  {
    chomp $line;
    @main::field = split " ",$line;
    
    my $src_ip = unpack "N", inet_aton ($main::field[0]);
    my $dst_ip = unpack "N", inet_aton ($main::field[44]);
    
    @csv_line = (); 
    
    @csv_line =  (  "\\N",   $src_ip,  # src_ip
                       $main::field[1],        #src_port
                       $main::field[2],        #src_packets
                       $main::field[12],       #src_syn
                       $main::field[3],        #src_rst
                       $main::field[4],        #src_ack
                       $main::field[13],       #src_fin
                       $dst_ip,		       #dst_ip
                       $main::field[45],       #dst_port 
                       $main::field[46],        #dst_packets
                       $main::field[56],       #dst_syn
                       $main::field[47],        #dst_rst
                       $main::field[48],        #dst_ack
                       $main::field[57],       #dst_fin
                       $main::field[89],       #start_time
                       $main::field[88],       #duration
                       $main::field[95],       #src_internal
                       is_internal($main::field[44]), # dst_internal
		       );
    my $status = $csv_obj->print($fh_csv,\@csv_line);
  }
}

# Close file

$fh_csv->close();
