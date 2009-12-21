#!/usr/bin/perl -w

use Text::CSV;
use IO::File;
use Socket;
use strict;

require 'check_internal.pl';

%main::html = ( 0=>"NONE",
         1=>"GET",
         2=>"POST",
         3=>"MSN",
         4=> "RTMPT",
         5=> "YOUTUBE",
         6=> "GOOGLEVIDEO",
         7=> "VIMEO",
         8=> "WIKI",
         9=> "RAPIDSHARE",
         10=>"MEGAUPLOAD",
         11=>"FACEBOOK",
         12=>"ADV",
         13=>"FLICKR",
         14=>"GMAPS",
         15=>"VOD",
);

# substitute here the CSV filename, that must be the same than the
# corresponding MySQL table

my $fh_csv = new IO::File ">tcp.csv";

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
                       $main::field[6],        #src data
                       $main::field[7],        #src_packets
                       $dst_ip,		       #dst_ip
                       $main::field[45],       #dst_port 
                       $main::field[50],       #dst_data
		       $main::field[51],       #dst_packets
                       $main::field[89],       #start_time
                       $main::field[88],       #duration
                       $main::field[95],       #src_internal
                       is_internal($main::field[44]), # dst_internal
                       $main::field[96],       #conn_type
                       $main::field[97],       #p2p_type
                       $main::field[99],       #ed2k_data
		       $main::field[100],      #ed2k_sig
		       $main::field[101],      #ed2k_c2s
		       $main::field[102],      #ed2k_s2c
		       $main::field[103],      #ed2k_msg
		       $main::field[20],       #src_max_seg_size
		       $main::field[64],       #dst_max_seg_size
                       $main::html{$main::field[104]},  # HTML classification
		       );
    my $status = $csv_obj->print($fh_csv,\@csv_line);
  }
}

# Close file

$fh_csv->close();
