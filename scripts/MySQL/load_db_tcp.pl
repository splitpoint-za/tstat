#!/usr/bin/perl -w

use DBI;
use strict;

require 'check_internal.pl';

%main::html = ( 0=>"NONE",
         1=>"GET",
         2=>"POST",
         3=>"MSN",
         4=> "RTMPT",
         5=> "YOUTUBE",
         6=> "VIDEOCONTENT",
         7=> "VIMEO",
         8=> "WIKI",
         9=> "RAPIDSHARE",
         10=>"MEGAUPLOAD",
         11=>"FACEBOOK",
         12=>"ADV",
         13=>"FLICKR",
         14=>"GMAPS",
         15=>"VOD",
         16=>"YOUTUBESITE",
	 17=>"SOCIAL",
	 18=>"FLASHVIDEO",
	 19=>"MEDIAFIRE",
	 20=>"HOTFILE",
	 21=>"STORAGE",
	 22=>"YOUTUBE204",
	 23=>"YOUTUBE204VIDEO",
	 24=>"YOUTUBESITEDIRECT",
	 25=>"YOUTUBESITEEMBED",
);

# substitute here the database name, username and password
# the user must have complete rights on the DB (or at least INSERT)
$main::dbh = DBI->connect("DBI:mysql:database","username","password");

$main::sth_tcp   = $main::dbh->prepare(
             "INSERT INTO tcp values (NULL,INET_ATON(?),?,?,?,INET_ATON(?),?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)");    
 
# We need to disable indexes and keys while loading the data,
# otherwise operations can be very slow for big files

$main::dbh->do("ALTER TABLE tcp DISABLE KEYS;");

{
 my $line;
 while($line = <>)
  {
    chomp $line;
    @main::field = split " ",$line;
    $main::sth_tcp->execute( $main::field[0],  # src_ip
                       $main::field[1],        #src_port
                       $main::field[6],        #src data
                       $main::field[7],        #src_packets
                       $main::field[44],       #dst_ip
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
  }
}

# Enable keys
$main::dbh->do("ALTER TABLE tcp ENABLE KEYS;");

$main::dbh->disconnect;
