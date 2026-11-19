package com.dnsguard.android

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.CopyOnWriteArrayList

object LogBus {
    private val listeners = CopyOnWriteArrayList<(String) -> Unit>()
    private val buffer = ArrayDeque<String>()
    private val fmt = SimpleDateFormat("HH:mm:ss", Locale.US)

    @Volatile
    var isRunning: Boolean = false

    @Synchronized
    fun log(msg: String) {
        val line = "[${fmt.format(Date())}] $msg"
        buffer.addLast(line)
        while (buffer.size > 80) buffer.removeFirst()
        listeners.forEach { it(line) }
    }

    @Synchronized
    fun snapshot(): String = buffer.joinToString("
")

    fun addListener(l: (String) -> Unit) = listeners.add(l)
    fun removeListener(l: (String) -> Unit) = listeners.remove(l)
}
