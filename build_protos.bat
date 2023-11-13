@echo off


::protoc -I=protobufs/ --go_out=src/proto/messages --go_opt=paths=source_relative --go-grpc_out=src/proto/messages --go-grpc_opt=paths=source_relative protobufs/messages.proto
python -m grpc_tools.protoc -I protobufs/ --python_out=sigilix_interface/proto/messages --grpc_python_out=sigilix_interface/proto/messages protobufs/messages.proto
::protoc -I=protobufs/ --go_out=src/proto/users --go_opt=paths=source_relative --go-grpc_out=src/proto/users --go-grpc_opt=paths=source_relative protobufs/users.proto
python -m grpc_tools.protoc -I protobufs/ --python_out=sigilix_interface/proto/users --grpc_python_out=sigilix_interface/proto/users protobufs/users.proto
