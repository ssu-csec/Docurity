Binary=$1
Tmpfile=$2
Output=$3
MAX_SIZE=$4
Operation1="Delete"
Operation2="finish"
echo "$0 ${Binary} ${Tmpfile} ${MAX_SIZE}" 

rm $Tmpfile
python3 -c "print('A'*${MAX_SIZE})" >> $Tmpfile
for ((i=1; i<$MAX_SIZE+1; i++))
do
	echo "${Operation1}" >> $Tmpfile
	echo "0" >> $Tmpfile
done
echo "${Operation2}" >> $Tmpfile

cat $Tmpfile |./$Binary > $Output
