Binary=$1
Tmpfile=$2
Output=$3
MAX_SIZE=$4
Operation="Insert"
echo "$0 ${Binary} ${Tmpfile} ${MAX_SIZE}" 

for ((i=1; i<$MAX_SIZE+1; i++))
do
	rm $Tmpfile
	echo "${Operation}" >> $Tmpfile
	echo "0" >> $Tmpfile
	python3 -c "print('A'*${i})" >> $Tmpfile
	cat $Tmpfile |xargs ./$Binary > $Output_$i
done

