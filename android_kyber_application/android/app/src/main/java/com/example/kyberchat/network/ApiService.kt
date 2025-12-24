package com.example.kyberchat.network

import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path

interface ApiService {
    @POST("/register")
    suspend fun register(@Body request: RegisterRequest): Response<RegisterResponse>

    @GET("/key/{clientId}")
    suspend fun getKey(@Path("clientId") clientId: String): Response<KeyResponse>
}
