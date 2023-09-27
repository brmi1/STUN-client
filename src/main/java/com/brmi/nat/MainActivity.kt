package com.brmi.nat

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import android.view.View
import android.widget.ProgressBar
import android.widget.TextView
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch

class MainActivity : AppCompatActivity() {

    private lateinit var progress_bar : ProgressBar
    private lateinit var type: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        progress_bar = findViewById(R.id.progress_bar)
        type = findViewById(R.id.type)

        GlobalScope.launch(Dispatchers.IO) {
            val stunClient = STUNClient()
            val result = stunClient.get_ip_info()
            launch(Dispatchers.Main) {
                type.text = result
                progress_bar.visibility = View.INVISIBLE
            }
        }
    }
}