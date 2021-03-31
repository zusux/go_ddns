package main

import (
	"github.com/gin-gonic/gin"
	"net"
)

func main() {
	r := gin.Default()
	r.GET("/", func(c *gin.Context) {
		ip, _, err := net.SplitHostPort(c.Request.RemoteAddr)
		if err != nil{
			c.String(200, err.Error())
		}else{
			c.String(200, ip)
		}

	})
	r.Run() // listen and serve on 0.0.0.0:8080
}