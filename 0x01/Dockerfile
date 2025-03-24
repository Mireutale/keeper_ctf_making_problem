FROM ubuntu:18.04

ENV user new
# ENV chall_port 7182

RUN apt-get update
RUN apt-get -y install socat
RUN apt-get install seccomp libseccomp-dev
RUN adduser $user

WORKDIR /home/$user

ADD $user /home/$user/$user
ADD ./nameOfKiller/KillerName

RUN chown -R root:root /home/$user
RUN chown root:$user /home/$user/KillerName
RUN chown root:$user /home/$user/$user

RUN chmod 755 /home/$user/$user
RUN chmod 440 /home/$user/KillerName

USER $user

# EXPOSE $chall_port
# CMD socat -T 30 TCP-LISTEN:$chall_port,reuseaddr,fork EXEC:/home/$user/$user