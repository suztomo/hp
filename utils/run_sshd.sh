#
# Run several SSH servers listening different ports.
# 
# run_sshd.sh <from_port> <to_port> [<skip>]

PROJECT_DIR=/home/suzuki/hp
SSHD_DIR=${PROJECT_DIR}/openssh

FROM_PORT_INDEX=$1
TO_PORT_INDEX=$2
SKIP=$3
if ! [ $2 ]; then
    echo "usage: $0 <from_port> <to_port> [<skip>]"
    exit
fi
if ! [ $3 ]; then
    SKIP=1;
fi

I=$FROM_PORT_INDEX
LOOP_COUNT=0

echo "Creating SSH Server listening [$FROM_PORT_INDEX:$TO_PORT_INDEX:$SKIP]"

while [ $I -lt $TO_PORT_INDEX ]; do
    echo ${SSHD_DIR}/sshd -f ${SSHD_DIR}/sshd_config -p $I
    ${SSHD_DIR}/sshd -f ${SSHD_DIR}/sshd_config -p $I
    I=`expr $I + $SKIP`
    LOOP_COUNT=`expr $LOOP_COUNT + 1`
done

echo "Created $LOOP_COUNT instances"



