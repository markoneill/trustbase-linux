#!/bin/bash

[ -f benchmark.txt ] && rm benchmark.txt

for i in 5000000 10000000 50000000 100000000 500000000
do
        [ -f tmp.txt ] && rm tmp.txt
        start_uri='https://192.168.21.101:4441/'
        end_uri='_size.gar'
        complete_uri=$start_uri$i$end_uri
        echo "For file: "$complete_uri >> benchmark.txt
        for x in {1..100}
        do
          	curl -w "@curl-format.txt" -o /dev/null -s --insecure $complete_uri | grep time_total | cut -d':' -f2 | tr -d ' ' >> tmp.txt
        done

	awk '{ total += $1; count++ } END { print total/count }' tmp.txt >> benchmark.txt
done
