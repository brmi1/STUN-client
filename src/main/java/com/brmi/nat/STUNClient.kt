package com.brmi.nat

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.SocketException
import java.util.Random

class STUNClient {

    private val SOURCE_PORT = 54320

    private val STUN_IP = "stun.ekiga.net"
    private val STUN_PORT = 3478

    private val SOCKET_TIMEOUT = 2000


    // stun attributes
    private val MappedAddress = "0001"
    private val ChangeRequest = "0003"
    private val SourceAddress = "0004"
    private val ChangedAddress = "0005"

    // types for a stun message
    private val BindRequestMsg = "0001"
    private val BindResponseMsg = "0101"


    fun stun_test(socket: DatagramSocket, host: String, port: Int, send_data: String = "") : Pair<Boolean, Map<String, Any>?> {
        fun a2bHex(hexStr: String): ByteArray {
            val byteArray = ByteArray(hexStr.length / 2)
            for (i in 0 until hexStr.length step 2) {
                val byteValue = hexStr.substring(i, i + 2).toInt(16)
                byteArray[i / 2] = byteValue.toByte()
            }

            return byteArray
        }

        fun b2aHexStr(abytes: ByteArray): String {
            val hexBytes = abytes.joinToString("") { "%02x".format(it) }
            return String(hexBytes.toByteArray(), Charsets.US_ASCII)
        }

        fun byteConvert(data: ByteArray, range: IntRange): String {
            val start = range.first
            val end = range.last + 1

            return data.sliceArray(start until end).joinToString("") { "%02x".format(it) }
        }

        fun extractIp(data: ByteArray, base: Int): String {
            val ipBytes = ByteArray(4)
            for (i in 0 until 4) {
                ipBytes[i] = data[base + 8 + i]
            }
            return ipBytes.joinToString(".") { (it.toInt() and 0xFF).toString() }
        }

        fun extractPort(data: ByteArray, base: Int): Int {
            val portBytes = (base + 6 until base + 8).map { data[it].toInt() and 0xFF }
            return (portBytes[0] shl 8) or portBytes[1]
        }

        val attrLen = send_data.length / 2
        val alignedLen = if (attrLen == 0) 0 else if (attrLen % 4 == 0) attrLen else attrLen + (4 - attrLen % 4)
        val strLen = "%04d".format(alignedLen)

        val tranid = (1..32).map { "0123456789ABCDEF"[Random().nextInt(16)] }.joinToString("")

        var data = a2bHex("$BindRequestMsg$strLen$tranid$send_data")
        var recvCorr = false

        while (!recvCorr) {
            var recieved = false
            var count = 3

            while (!recieved) {
                try {
                    socket.send(DatagramPacket(data, data.size, InetAddress.getByName(host), port))
                } catch (e: SocketException) {
                    // Обработка ошибки DNS (socket.gaierror) - вернуть false, null
                    return false to null
                }

                try {
                    val buffer = ByteArray(2048)
                    val packet = DatagramPacket(buffer, buffer.size)
                    socket.receive(packet)

                    data = packet.data

                    recieved = true
                } catch (e: Exception) {
                    recieved = false

                    if (count > 0) {
                        count -= 1
                    } else {
                        return false to null
                    }
                }
            }

            if (b2aHexStr(data.sliceArray(0 until 2)) == BindResponseMsg) {
                recvCorr = true
            }

            var lenRemain = byteConvert(data, 2 until 4).toInt(16)
            var base = 20

            var externalIP = ""
            var externalPort = 0
            var sourceIP = ""
            var sourcePort = 0
            var changedIP = ""
            var changedPort = 0

            while (lenRemain > 0) {
                val attrType = byteConvert(data, base until base + 2)
                val attrLen = byteConvert(data, base + 2 until base + 4).toInt(16)

                if (attrType == MappedAddress) {
                    externalIP = extractIp(data, base)
                    externalPort = extractPort(data, base)
                }

                if (attrType == SourceAddress) {
                    sourceIP = extractIp(data, base)
                    sourcePort = extractPort(data, base)
                }

                if (attrType == ChangedAddress) {
                    changedIP = extractIp(data, base)
                    changedPort = extractPort(data, base)
                }

                base += 4 + attrLen
                lenRemain -= (4 + attrLen)
            }

            val dataMap = mapOf(
                "ExternalIP" to externalIP,
                "ExternalPort" to externalPort,
                "SourceIP" to sourceIP,
                "SourcePort" to sourcePort,
                "ChangedIP" to changedIP,
                "ChangedPort" to changedPort
            )

            return true to dataMap
        }

        return false to null
    }

    fun get_ip_info() : String {
        val socket = DatagramSocket(SOURCE_PORT)
        socket.reuseAddress = true
        socket.soTimeout = SOCKET_TIMEOUT


        val (result, data) = stun_test(socket, STUN_IP, STUN_PORT)

        if (result) {
            val dataList = data?.values?.toList()

            val (ExternalIP, ExternalPort) = Pair(dataList?.getOrNull(0), dataList?.getOrNull(1))
            // val (SourceIP, SourcePort) = Pair(dataList?.getOrNull(2), dataList?.getOrNull(3))
            val (ChangedIP, ChangedPort) = Pair(dataList?.getOrNull(4), dataList?.getOrNull(5))

            val changeRequest = "$ChangeRequest" + "0004" + "00000006"
            val (result, data) = stun_test(socket, STUN_IP, STUN_PORT, send_data=changeRequest)

            if (result) { // Fullcone
                return "Public IP: " + data?.get("ExternalIP") + "\nPublic Port: " + data?.get("ExternalPort") + "\nNAT type: Fullcone"
            } else {
                val (result, data) = stun_test(socket, ChangedIP as String, ChangedPort as Int)

                if (result) {
                    if (ExternalIP == data?.get("ExternalIP") && ExternalPort == data?.get("ExternalPort")) {
                        val (result, data) = stun_test(socket, ChangedIP, STUN_PORT)

                        if (result) { // Restric
                            return "Public IP: " + data?.get("ExternalIP") + "\nPublic Port: " + data?.get("ExternalPort") + "\nNAT type: Restric"
                        } else { // PortRestric
                            return "Public IP: " + data?.get("ExternalIP") + "\nPublic Port: " + data?.get("ExternalPort") + "\nNAT type: PortRestric"
                        }
                    } else { // Symmetric
                        return "Public IP: " + data?.get("ExternalIP") + "\nPublic Port: " + data?.get("ExternalPort") + "\nNAT type: Symmetric"
                    }
                }
            }
        }

        return "Unknown error"
    }
}
