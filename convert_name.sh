#! /bin/bash

function zero()
{
folder="/home/cnmfs/projects/oreilly-safaribooks/Books/"

#for file in *; 
for file in ./Books/* ;
do 
#	new_file=$(echo "$file"  | sed -e 's/[^A-Za-z0-9/._-]/_/g')
#	echo $file 
#	echo $new_file
	mv "$file" $(echo "$file" | sed -e 's/[^A-Za-z0-9._-]/_/g');
 done ;
}

function first()
{
	for file in /home/cnmfs/projects/oreilly-safaribooks/Books/* ;
	do
   		mv -- "$file" "${file// /_}";
	done
}
function second()
{
        for file in /home/cnmfs/projects/oreilly-safaribooks/Books/* ;
        do
                mv -- "$file" "${file// /_}";
        done
}



#for file in Books/* ; do   mv -- "$file" "${file//"\\\\'"/_}"; done

zero
#first
#second

