package mgmt

// EmailTemplate is a ready-to-use email body for the send form. Body is HTML
// and may contain {{.Link}} (the per-recipient phishing link) and {{.Pixel}}
// (the open-tracking pixel; when absent it is appended automatically to HTML).
type EmailTemplate struct {
	ID      string
	Name    string
	Subject string
	Body    string
	// FromEmail and FromName pre-fill the sender-spoofing fields of the send
	// form when the operator picks this template. Empty means "leave the
	// operator's current From untouched".
	FromEmail string
	FromName  string
}

// BuiltinEmailTemplates are starting points an operator can pick in the send
// form, then edit. They are deliberately generic pretexts; the operator adapts
// the branding to the authorized target in the RoE.
var BuiltinEmailTemplates = []EmailTemplate{
	{
		ID:      "m365-verify",
		Name:    "Microsoft 365 — Vérification requise",
		Subject: "Action requise : vérifiez votre compte Microsoft 365",
		Body: `<p>Bonjour,</p>
<p>Notre système a détecté une activité inhabituelle sur votre compte Microsoft 365.
Pour éviter la suspension de votre accès, veuillez vérifier votre identité dès maintenant.</p>
<p><a href="{{.Link}}">Vérifier mon compte</a></p>
<p>Si vous ne reconnaissez pas cette activité, cette vérification protège votre compte.</p>
<p>Cordialement,<br>Support Microsoft 365</p>`,
	},
	{
		ID:      "security-login",
		Name:    "Alerte sécurité — Connexion inhabituelle",
		Subject: "Alerte de sécurité : nouvelle connexion détectée",
		Body: `<p>Bonjour,</p>
<p>Une connexion à votre compte vient d'être effectuée depuis un nouvel appareil.
Si vous n'êtes pas à l'origine de cette connexion, sécurisez votre compte immédiatement.</p>
<p><a href="{{.Link}}">Sécuriser mon compte</a></p>
<p>Ce lien expire dans 24 heures.</p>
<p>L'équipe Sécurité</p>`,
	},
	{
		ID:      "hr-document",
		Name:    "RH — Document à signer",
		Subject: "Document RH en attente de votre signature",
		Body: `<p>Bonjour,</p>
<p>Un document vous concernant est en attente de signature électronique dans l'espace RH.
Merci de le consulter et de le signer avant la fin de la semaine.</p>
<p><a href="{{.Link}}">Accéder au document</a></p>
<p>Bien cordialement,<br>Service des Ressources Humaines</p>`,
	},
	{
		ID:      "it-password",
		Name:    "Service informatique — Mise à jour du mot de passe",
		Subject: "Votre mot de passe expire aujourd'hui",
		Body: `<p>Bonjour,</p>
<p>Conformément à notre politique de sécurité, votre mot de passe expire aujourd'hui.
Veuillez le renouveler pour conserver l'accès à vos outils.</p>
<p><a href="{{.Link}}">Renouveler mon mot de passe</a></p>
<p>Sans action de votre part, votre accès sera temporairement suspendu.</p>
<p>Le Service Informatique</p>`,
	},
}
