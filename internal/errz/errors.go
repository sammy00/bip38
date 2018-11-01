package errz

// Fatal panick on non-nil error
func Fatal(err error) {
	if nil != err {
		panic(err)
	}
}
