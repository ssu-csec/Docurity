Binary=$1
Tmpfile=$2
Output=$3
MAX_SIZE=$4
Operation="Delete"
echo "$0 ${Binary} ${Tmpfile} ${MAX_SIZE}" 

rm $Tmpfile
python3 -c "print('A'*${MAX_SIZE})" >> $Tmpfile
for ((i=1; i<$MAX_SIZE+1; i++))
do
	echo "${Operation}" >> $Tmpfile
	echo "0" >> $Tmpfile
done

cat $Tmpfile |xargs ./$Binary > $Output
