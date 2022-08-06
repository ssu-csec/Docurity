Binary=$1
Tmpfile=$2
Output=$3
MAX_SIZE=$4
Operation1="Insert"
Operation2="Delete"
Operation3="finish"
echo "$0 ${Binary} ${Tmpfile} ${MAX_SIZE}" 

rm $Tmpfile

# Initial data
echo "${Operation1}" >> $Tmpfile
echo "0" >> $Tmpfile
python3 -c "print('A'*${MAX_SIZE})" >> $Tmpfile

for ((i=1; i<$MAX_SIZE+1; i++))
do
	random_operation=$(($RANDOM % 2))
	random_index=$(($RANDOM % ($MAX_SIZE / 2)))

	if [ $random_operation -eq 1 ]
	then
		echo "${Operation1}" >> $Tmpfile
		echo $random_index >> $Tmpfile
		python3 -c "print('A')" >> $Tmpfile
	else
		echo "${Operation2}" >> $Tmpfile
		echo $random_index >> $Tmpfile
		echo "1" >> $Tmpfile
	fi
done
echo "${Operation3}" >> $Tmpfile

cat $Tmpfile |./$Binary > $Output
