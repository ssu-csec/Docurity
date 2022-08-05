Binary=$1
Tmpfile=$2
Output=$3
MAX_SIZE=$4
Operation1="Insert"
Operation2="finish"
echo "$0 ${Binary} ${Tmpfile} ${MAX_SIZE}" 

for ((i=1; i<$MAX_SIZE+1; i++))
do
	rm $Tmpfile
	echo "${Operation1}" >> $Tmpfile
	echo "0" >> $Tmpfile
	python3 -c "print('A'*${i})" >> $Tmpfile
	echo "${Operation2}" >> $Tmpfile
	cat $Tmpfile |./$Binary > ${Output}_${i}
done

