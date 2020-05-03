/****************************** Module Header ******************************\
* Module Name:  NetFuzz.cpp
* Project:      NetFuzz
* Copyright (c) 2020 Stanislav Denisov
*
* Fiber-based networking fuzzer for testing the reliable UDP transports
*
* This source is subject to the Microsoft Public License.
* See https://opensource.org/licenses/MS-PL
* All other rights reserved.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
* EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
\***************************************************************************/

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <queue>
#include "Argparse/argparse.h" // https://github.com/jamolnng/argparse
#include "ENet/enet.h" // https://github.com/nxrighthere/ENet-CSharp
#include <conio.h>
#include <Windows.h>

#define NET_TRANSPORT_HYPERNET 0
#define NET_TRANSPORT_ENET 1

#define NET_MAX_CLIENTS 256
#define NET_MAX_CHANNELS 2

#define NET_FUZZING_CONNECTIONS_ITERATIONS 1000
#define NET_FUZZING_MESSAGES_ITERATIONS 100

static const char* libraries[] = {
	"HyperNet",
	"ENet"
};

static uint8_t data[1024];
static int16_t initialLine;
static HANDLE consoleHandle;

static int32_t networkingLibrary;
static int32_t clientsCount = NET_MAX_CLIENTS;
static uint16_t port = 9500;

static bool serverSuspended;
static int32_t clientsSuspendedCount;
static int32_t clientsSpawnedCount;
static int32_t clientsConnectedCount;
static int32_t clientsConnectionIterationsCount;
static int32_t clientsDisconnectionIterationsCount;
static int32_t clientsMessagesCount;
static int32_t clientDisconnectedCount;

namespace fibers {
	static std::deque<void*> queue;

	inline void schedule() {
		void* fiber = queue.front();

		queue.pop_front();
		queue.push_back(fiber);

		SwitchToFiber(fiber);
	}

	inline void suspend() {
		queue.pop_back();

		schedule();
	}
}

void Line(int16_t line) {
	COORD coord;

	coord.X = 0;
	coord.Y = line;

	SetConsoleCursorPosition(consoleHandle, coord);
}

uint8_t* Random(uint8_t* buffer) {
	for (int32_t i = 0; i < 1 + rand() % sizeof(buffer); i++) {
		buffer[i] = rand() % 256;
	}

	return buffer;
}

void Supervisor(void* main) {
	std::cout << std::endl;

	while (true) {
		Line(initialLine + 1);

		std::cout << "Phase 1: Spawning (" << clientsSpawnedCount << "/" << clientsCount << ")" << std::endl;

		if (clientsSpawnedCount == clientsCount)
			break;

		if (serverSuspended && clientsSuspendedCount == clientsCount)
			goto main;

		fibers::schedule();
	}

	std::cout << std::endl;

	while (true) {
		Line(initialLine + 2);

		std::cout << "Phase 2: Connections (" << clientsDisconnectionIterationsCount << "/" << NET_FUZZING_CONNECTIONS_ITERATIONS << ")" << std::endl;

		if (clientsConnectedCount == clientsCount && clientsConnectionIterationsCount == NET_FUZZING_CONNECTIONS_ITERATIONS && clientsDisconnectionIterationsCount == NET_FUZZING_CONNECTIONS_ITERATIONS)
			break;

		if (serverSuspended && clientsSuspendedCount == clientsCount)
			goto main;

		fibers::schedule();
	}

	std::cout << std::endl;

	while (true) {
		Line(initialLine + 3);

		std::cout << "Phase 3: Transmission (" << clientsMessagesCount << "/" << clientsCount * NET_FUZZING_MESSAGES_ITERATIONS * 2 << ")" << std::endl;

		if (clientsMessagesCount == clientsCount * NET_FUZZING_MESSAGES_ITERATIONS * 2)
			break;

		if (serverSuspended && clientsSuspendedCount == clientsCount)
			goto main;

		fibers::schedule();
	}

	std::cout << std::endl;

	while (true) {
		Line(initialLine + 4);

		std::cout << "Phase 4: Disconnections (" << clientDisconnectedCount << "/" << clientsCount << ")" << std::endl;

		if (clientDisconnectedCount == clientsCount)
			break;

		if (serverSuspended && clientsSuspendedCount == clientsCount)
			goto main;

		fibers::schedule();
	}

	std::cout << "Done!" << std::endl;

	main:

	SwitchToFiber(main);
}

void Server(void* main) {
	if (networkingLibrary == NET_TRANSPORT_HYPERNET) {

	} else if (networkingLibrary == NET_TRANSPORT_ENET) {
		ENetAddress address = { };

		address.port = port;

		ENetHost* host = nullptr;

		if (enet_address_set_hostname(&address, "::1") < 0) {
			std::cout << "Server hostname assigment failed!" << std::endl;

			abort();
		} else {
			if ((host = enet_host_create(&address, clientsCount, NET_MAX_CHANNELS, 0, 0, 1024 * 1024)) == nullptr) {
				std::cout << "Server creation failed!" << std::endl;

				abort();
			}
		}

		ENetEvent event = { };

		while (!_kbhit()) {
			bool polled = false;

			while (!polled) {
				if (enet_host_check_events(host, &event) <= 0) {
					if (enet_host_service(host, &event, 0) <= 0)
						break;

					polled = true;
				}

				switch (event.type) {
					case ENET_EVENT_TYPE_NONE:
						break;

					case ENET_EVENT_TYPE_CONNECT: {
						clientsConnectedCount = host->connectedPeers;

						if (clientsConnectionIterationsCount < NET_FUZZING_CONNECTIONS_ITERATIONS) {
							clientsConnectionIterationsCount++;

							enet_peer_disconnect(event.peer, 0);
						} else {
							ENetPacket* packet = enet_packet_create(Random(data), sizeof(data), ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(event.peer, 1, packet);
						}

						break;
					}

					case ENET_EVENT_TYPE_DISCONNECT: case ENET_EVENT_TYPE_DISCONNECT_TIMEOUT: {
						clientsDisconnectionIterationsCount++;

						break;
					}

					case ENET_EVENT_TYPE_RECEIVE:
						clientsMessagesCount++;

						enet_packet_destroy(event.packet);

						if (clientsMessagesCount < clientsCount * NET_FUZZING_MESSAGES_ITERATIONS * 2) {
							ENetPacket* packet = enet_packet_create(Random(data), sizeof(data), ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(event.peer, 1, packet);
						} else {
							enet_peer_disconnect(event.peer, 0);
						}

						break;
				}
			}

			fibers::schedule();
		}

		enet_host_flush(host);
		enet_host_destroy(host);
	}

	serverSuspended = true;

	while (true) {
		fibers::suspend();
	}
}

void Client(void* main) {
	if (networkingLibrary == NET_TRANSPORT_HYPERNET) {

	} else if (networkingLibrary == NET_TRANSPORT_ENET) {
		ENetAddress address = { };

		address.port = port;

		ENetHost* host = nullptr;
		ENetPeer* peer = nullptr;

		if (enet_address_set_hostname(&address, "::1") < 0) {
			std::cout << "Client hostname assigment failed!" << std::endl;

			abort();
		} else {
			if ((host = enet_host_create(nullptr, 1, 0, 0, 0, 1024 * 1024)) == nullptr) {
				std::cout << "Client creation failed!" << std::endl;

				abort();
			} else {
				clientsSpawnedCount++;

				if ((peer = enet_host_connect(host, &address, NET_MAX_CHANNELS, 0)) == nullptr) {
					std::cout << "Client connection failed!" << std::endl;

					abort();
				}
			}
		}

		ENetEvent event = { };

		while (!_kbhit()) {
			bool polled = false;

			while (!polled) {
				if (enet_host_check_events(host, &event) <= 0) {
					if (enet_host_service(host, &event, 0) <= 0)
						break;

					polled = true;
				}

				switch (event.type) {
					case ENET_EVENT_TYPE_NONE:
						break;

					case ENET_EVENT_TYPE_CONNECT:
						break;

					case ENET_EVENT_TYPE_DISCONNECT: case ENET_EVENT_TYPE_DISCONNECT_TIMEOUT: {
						if (clientsMessagesCount < clientsCount * NET_FUZZING_MESSAGES_ITERATIONS * 2) {
							if ((peer = enet_host_connect(host, &address, NET_MAX_CHANNELS, 0)) == nullptr) {
								std::cout << "Client connection failed!" << std::endl;

								abort();
							}
						} else {
							clientDisconnectedCount++;
						}

						break;
					}

					case ENET_EVENT_TYPE_RECEIVE: {
						clientsMessagesCount++;

						enet_packet_destroy(event.packet);

						ENetPacket* packet = enet_packet_create(Random(data), sizeof(data), ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 1, packet);

						break;
					}
				}
			}

			fibers::schedule();
		}

		enet_host_flush(host);
		enet_host_destroy(host);
	}

	clientsSuspendedCount++;

	while (true) {
		fibers::suspend();
	}
}

int main(int argumentsCount, const char* arguments[]) {
	system("cls");

	argparse::ArgumentParser parser("NetFuzz");

	parser.add_argument()
		.names({"-l", "--library"})
		.description("Networking library identifier")
		.required(true);

	parser.add_argument()
		.names({"-c", "--clients"})
		.description("Number of simulated clients");

	parser.add_argument()
		.names({"-p", "--port"})
		.description("Port number for connection establishment");

	parser.enable_help();

	auto parserError = parser.parse(argumentsCount, arguments);

	if (parserError) {
		std::cout << parserError << std::endl;

		return -1;
	}

	if (parser.exists("help")) {
		parser.print_help();
	} else {
		if (parser.exists("library")) {
			networkingLibrary = parser.get<int32_t>("library");

			if (networkingLibrary > sizeof(libraries) / sizeof(char*) - 1) {
				std::cout << "Invalid networking library, please, set the correct identifier!" << std::endl;

				return -1;
			}
		}

		if (parser.exists("clients"))
			clientsCount = parser.get<int32_t>("clients");

		if (parser.exists("port"))
			port = parser.get<uint16_t>("port");

		std::cout << "Networking library: " << libraries[networkingLibrary] << std::endl
			<< "Number of clients: " << clientsCount << std::endl
			<< "Initialization..." << std::endl;

		consoleHandle = GetStdHandle(STD_OUTPUT_HANDLE);

		CONSOLE_SCREEN_BUFFER_INFO screenInfo;

		GetConsoleScreenBufferInfo(consoleHandle, &screenInfo);

		initialLine = screenInfo.dwCursorPosition.Y;

		CONSOLE_CURSOR_INFO cursorInfo;

		GetConsoleCursorInfo(consoleHandle, &cursorInfo);

		cursorInfo.bVisible = false;

		SetConsoleCursorInfo(consoleHandle, &cursorInfo);

		if (networkingLibrary == NET_TRANSPORT_HYPERNET) {
			std::cout << libraries[networkingLibrary] << " is not implemented!" << std::endl;

			abort();
		} else if (networkingLibrary == NET_TRANSPORT_ENET) {
			enet_initialize();
		}

		void* main = ConvertThreadToFiber(nullptr);
		void* supervisor = CreateFiber(0, Supervisor, main);
		void* server = CreateFiber(0, Server, main);

		for (int32_t i = 0; i < clientsCount; i++) {
			fibers::queue.push_back(supervisor);
			fibers::queue.push_back(server);
			fibers::queue.push_back(CreateFiber(0, Client, main));
		}

		std::cout << "Fuzzing..." << std::endl;

		fibers::schedule();

		std::cout << "Deitialization..." << std::endl;

		if (networkingLibrary == NET_TRANSPORT_HYPERNET) {

		} else if (networkingLibrary == NET_TRANSPORT_ENET) {
			enet_deinitialize();
		}
	}

	return 0;
}
