function run(){
  cd build && LANG_LOCAL=$lang_local cmake .. 1>/dev/null && make 1>/dev/null && cd .. && ./build/src/os_rsa_lab
}
echo "1) ENG"
echo "2) UKR"
echo "3) RUS"
read choice
case $choice in
  1)
    lang_local=1
    run
    ;;
  2)
    lang_local=2
    run
    ;;
  3)
    lang_local=3
    run
    ;;
  *)
    echo "Invalid choice"
    ;;
esac
