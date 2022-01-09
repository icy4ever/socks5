package server

type BasicAuth struct {
	Username string
	Password string
}

func (b BasicAuth) Verify(params ...interface{}) bool {
	if len(params) != 2 {
		return false
	}
	username, ok := params[0].(string)
	if !ok {
		return false
	}
	password, ok := params[1].(string)
	if !ok {
		return false
	}
	return b.Username == username && b.Password == password
}

func (b BasicAuth) GetCode() int {
	return 2
}
