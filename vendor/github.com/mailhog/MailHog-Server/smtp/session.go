package smtp

// http://www.rfc-editor.org/rfc/rfc5321.txt

import (
	"io"
	"log"
	netsmtp "net/smtp"
	"strings"

	"github.com/ian-kent/linkio"
	"github.com/mailhog/MailHog-Server/config"
	"github.com/mailhog/MailHog-Server/monkey"
	"github.com/mailhog/data"
	"github.com/mailhog/smtp"
	"github.com/mailhog/storage"
)

// Session represents a SMTP session using net.TCPConn
type Session struct {
	conn          io.ReadWriteCloser
	proto         *smtp.Protocol
	storage       storage.Storage
	messageChan   chan *data.Message
	remoteAddress string
	isTLS         bool
	line          string
	link          *linkio.Link
	config        *config.Config

	reader io.Reader
	writer io.Writer
	monkey monkey.ChaosMonkey
}

// ReleaseConfig is an alias to preserve go package API
type ReleaseConfig config.OutgoingSMTP

// Accept starts a new SMTP session using io.ReadWriteCloser
func Accept(remoteAddress string, conn io.ReadWriteCloser, cfg *config.Config) {
	storage := cfg.Storage
	messageChan := cfg.MessageChan
	hostname := cfg.Hostname
	monkey := cfg.Monkey

	defer conn.Close()

	proto := smtp.NewProtocol()
	proto.Hostname = hostname
	var link *linkio.Link
	reader := io.Reader(conn)
	writer := io.Writer(conn)
	if monkey != nil {
		linkSpeed := monkey.LinkSpeed()
		if linkSpeed != nil {
			link = linkio.NewLink(*linkSpeed * linkio.BytePerSecond)
			reader = link.NewLinkReader(io.Reader(conn))
			writer = link.NewLinkWriter(io.Writer(conn))
		}
	}

	session := &Session{conn, proto, storage, messageChan, remoteAddress, false, "", link, cfg, reader, writer, monkey}
	proto.LogHandler = session.logf
	proto.MessageReceivedHandler = session.acceptMessage
	proto.ValidateSenderHandler = session.validateSender
	proto.ValidateRecipientHandler = session.validateRecipient
	proto.ValidateAuthenticationHandler = session.validateAuthentication
	proto.GetAuthenticationMechanismsHandler = func() []string { return []string{"PLAIN"} }

	session.logf("Starting session")
	session.Write(proto.Start())
	for session.Read() == true {
		if monkey != nil && monkey.Disconnect != nil && monkey.Disconnect() {
			session.conn.Close()
			break
		}
	}
	session.logf("Session ended")
}

func (c *Session) validateAuthentication(mechanism string, args ...string) (errorReply *smtp.Reply, ok bool) {
	if c.monkey != nil {
		ok := c.monkey.ValidAUTH(mechanism, args...)
		if !ok {
			// FIXME better error?
			return smtp.ReplyUnrecognisedCommand(), false
		}
	}
	return nil, true
}

func (c *Session) validateRecipient(to string) bool {
	if c.monkey != nil {
		ok := c.monkey.ValidRCPT(to)
		if !ok {
			return false
		}
	}
	return true
}

func (c *Session) validateSender(from string) bool {
	if c.monkey != nil {
		ok := c.monkey.ValidMAIL(from)
		if !ok {
			return false
		}
	}
	return true
}

func (c *Session) acceptMessage(msg *data.SMTPMessage) (id string, err error) {
	m := msg.Parse(c.proto.Hostname, c.config.EnvironmentLabel)
	c.logf("Storing message %s", m.ID)
	id, err = c.storage.Store(m)
	go c.release(m)
	c.messageChan <- m
	return
}

func (c *Session) release(msg *data.Message) {
	var releaseCfg ReleaseConfig
	if cfg, ok := c.config.OutgoingSMTP["AutoRelease"]; ok {
		c.logf("Using server with name: AutoRelease")
		releaseCfg.Name = cfg.Name
		if len(cfg.Email) == 0 {
			releaseCfg.Email = cfg.Email
		}
		releaseCfg.Host = cfg.Host
		releaseCfg.Port = cfg.Port
		releaseCfg.Username = cfg.Username
		releaseCfg.Password = cfg.Password
		releaseCfg.Mechanism = cfg.Mechanism
	} else {
		return
	}

	c.logf("Releasing to %s (via %s:%s)", releaseCfg.Email, releaseCfg.Host, releaseCfg.Port)

	bytes := make([]byte, 0)
	for h, l := range msg.Content.Headers {
		for _, v := range l {
			bytes = append(bytes, []byte(h+": "+v+"\r\n")...)
		}
	}
	bytes = append(bytes, []byte("\r\n"+msg.Content.Body)...)

	var auth netsmtp.Auth

	if len(releaseCfg.Username) > 0 || len(releaseCfg.Password) > 0 {
		c.logf("Found username/password, using auth mechanism: [%s]", releaseCfg.Mechanism)
		switch releaseCfg.Mechanism {
		case "CRAMMD5":
			auth = netsmtp.CRAMMD5Auth(releaseCfg.Username, releaseCfg.Password)
		case "PLAIN":
			auth = netsmtp.PlainAuth("", releaseCfg.Username, releaseCfg.Password, releaseCfg.Host)
		default:
			c.logf("Error - invalid authentication mechanism")
			return
		}
	}

	err := netsmtp.SendMail(releaseCfg.Host+":"+releaseCfg.Port, auth, msg.Content.Headers["From"][0], msg.Content.Headers["To"], bytes)
	if err != nil {
		c.logf("Failed to release message: %s (Host: %s, From: %s, To: %s)", err, releaseCfg.Host+":"+releaseCfg.Port, msg.Content.Headers["From"][0], msg.Content.Headers["To"])
		return
	}
	c.logf("Message released successfully")
}

func (c *Session) logf(message string, args ...interface{}) {
	message = strings.Join([]string{"[SMTP %s]", message}, " ")
	args = append([]interface{}{c.remoteAddress}, args...)
	log.Printf(message, args...)
}

// Read reads from the underlying net.TCPConn
func (c *Session) Read() bool {
	buf := make([]byte, 1024)
	n, err := c.reader.Read(buf)

	if n == 0 {
		c.logf("Connection closed by remote host\n")
		io.Closer(c.conn).Close() // not sure this is necessary?
		return false
	}

	if err != nil {
		c.logf("Error reading from socket: %s\n", err)
		return false
	}

	text := string(buf[0:n])
	logText := strings.Replace(text, "\n", "\\n", -1)
	logText = strings.Replace(logText, "\r", "\\r", -1)
	c.logf("Received %d bytes: '%s'\n", n, logText)

	c.line += text

	for strings.Contains(c.line, "\r\n") {
		line, reply := c.proto.Parse(c.line)
		c.line = line

		if reply != nil {
			c.Write(reply)
			if reply.Status == 221 {
				io.Closer(c.conn).Close()
				return false
			}
		}
	}

	return true
}

// Write writes a reply to the underlying net.TCPConn
func (c *Session) Write(reply *smtp.Reply) {
	lines := reply.Lines()
	for _, l := range lines {
		logText := strings.Replace(l, "\n", "\\n", -1)
		logText = strings.Replace(logText, "\r", "\\r", -1)
		c.logf("Sent %d bytes: '%s'", len(l), logText)
		c.writer.Write([]byte(l))
	}
}
