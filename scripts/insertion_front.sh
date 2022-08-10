Binary=$1
Tmpfile=$2
Output=$3
MAX_SIZE=$4
Threshold=1024*1024
#Start=1024*1024*10
Start=120000000
Operation="Insert"
echo "$0 ${Binary} ${Tmpfile} ${MAX_SIZE}" 

rm $Tmpfile

echo "${Operation}" >> $Tmpfile
echo "0" >> $Tmpfile
./string_printer $Start >> $Tmpfile
for ((i=1; i<$MAX_SIZE+1; i++))
do
	echo "${Binary} ${i}" 
	echo "${Operation}" >> $Tmpfile
	echo "2" >> $Tmpfile
	./string_printer $(($i * Threshold)) >> $Tmpfile
done

./$Binary $Tmpfile> $Output
