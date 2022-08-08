Binary=$1
Tmpfile=$2
Output=$3
MAX_SIZE=$4
Threshold=1024
Operation="Insert"
echo "$0 ${Binary} ${Tmpfile} ${MAX_SIZE}" 

for ((i=1; i<$MAX_SIZE+1; i++))
do
	echo "${Binary} ${i}" 
	rm $Tmpfile
	echo "${Operation}" >> $Tmpfile
	echo "0" >> $Tmpfile
	./string_printer $(($i * Threshold)) >> $Tmpfile
	./$Binary $Tmpfile> ${Output}_${i}
done

