Binary=$1
Tmpfile=$2
Output=$3
MAX_SIZE=$4
Operation1="Insert"
Operation2="finish"
echo "$0 ${Binary} ${Tmpfile} ${MAX_SIZE}" 

rm $Tmpfile
for ((i=1; i<$MAX_SIZE+1; i++))
do
	echo "${Operation1}" >> $Tmpfile
	echo "1" >> $Tmpfile
	python3 -c "print('A')" >> $Tmpfile
done
echo "${Operation2}" >> $Tmpfile

cat $Tmpfile |./$Binary >$Output
