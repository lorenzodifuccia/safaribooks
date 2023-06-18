#!/bin/bash
book_ids=9780134278308,9780134278308 #sample book_ids
IFS=','
for book_id in $book_ids; do
	echo "downloading book with id $book_id"
	python3 safaribooks.py --cred "email:password" $book_id
done

