printf "Creating installation package\n"
printf "Checklist:\n"
printf "* Angular Admin Version Check. \n"
printf "* Janusec Version Check. \n"
version="1.3.3"
printf "Version: ${version} \n"

read -r -p "Are You Sure? [Y/n] " option

case $option in
[yY]) printf "Continue \n"
;;
[nN]) printf "Bye! \n"
exit 0
;;
*) printf "Invalid option. \n"
exit 1
;;
esac

function buildFor() {
    filename_prefix="janusec-${version}-$1"
    temp_dir="./dist/${filename_prefix}/"
    mkdir -p ${temp_dir}
    \cp -f ./janusec ${temp_dir}
    \cp -f ./3rdpartylicenses.txt ${temp_dir}
    rm -rf ${temp_dir}static
    mkdir ${temp_dir}static
    \cp -r ./static/janusec-admin ${temp_dir}static/
    \cp -r ./static/welcome ${temp_dir}static/
    \cp -f ./robots.txt ${temp_dir}static/
    \cp -f ./scripts/* ${temp_dir}
    cd ./dist/
    tar -zcf ./${filename_prefix}.tar.gz ./${filename_prefix}
    rm -rf ./${filename_prefix}
    cd ..
}

printf "Building amd64 ... \n"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build janusec.go
buildFor amd64
printf "amd64 done!\n"

printf "Building arm64 ... \n"
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build janusec.go
buildFor arm64
printf "arm64 done!\n"

printf "Building mips64 ... \n"
CGO_ENABLED=0 GOOS=linux GOARCH=mips64 go build janusec.go
buildFor mips64
printf "mips64 done!\n"

printf "Building mips64le ... \n"
CGO_ENABLED=0 GOOS=linux GOARCH=mips64le go build janusec.go
buildFor mips64le
printf "mips64le done!\n"

printf "Done!\n"
