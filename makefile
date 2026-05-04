clean:
	rm -rf data/*

test1:
	py -3.11 -m tests.test_module1

test3:
	py -3.11 -m tests.test_module3

testlocalflow:
	py -3.11 -m tests.test_localworkflow

cli:
	py -3.11 -m src.cli.main

gui: 
	py -3.11 password_manager_gui.py