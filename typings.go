package gatemanpublic

// GatemanPayload struct describes the data which Gateman seals into a token
// and unseals from a token.
type GatemanPayload struct {
	Id      string      `json:"id"`
	Role    string      `json:"role"`
	Service string      `json:"service"`
	Data    interface{} `json:"data"`
}

//GatemanOptions struct the basic struct to init gateman
type GatemanOptions struct {
	Service         string
	AuthScheme      string
	Redis           string
	Secret          string
	SessionDuration string
}

//CreateSessionOptions struct to create a session
type CreateSessionOptions struct {
	ID              string
	Role            string
	SessionDuration int
	Data            interface{}
}

//CreateHeadlessTokenOptions struct, to create a headless token
type CreateHeadlessTokenOptions struct {
	ID   string
	Data interface{}
}

//ValidateRoleOptions struct
type ValidateRoleOptions struct {
	ServiceAuthScheme string
	Scheme            string
	Role              []string
	Service           []string
	Data              GatemanPayload
}

//IRedisService interface for redis operations
type IRedisService interface {
	hdel(hash string, field string) interface{}
	hget(hash string, field string) string
	hgetall(key string)
	hset(hash string, field string, value interface{})
	quit()
	set(key string, value interface{}, mode string, duration int)
	get(key string)
	del(key string)
}
