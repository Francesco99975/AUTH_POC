package enums

type MessageKind string

const (
	InfoToast    MessageKind = "info"
	SuccessToast MessageKind = "success"
	WarningToast MessageKind = "warning"
	ErrorToast   MessageKind = "error"
)
