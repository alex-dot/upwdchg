<!-- INDENTING (emacs/vi): -*- mode:html; tab-width:2; c-basic-offset:2; intent-tabs-mode:nil; -*- ex: set tabstop=2 expandtab: -->
<?php
/** Universal Password Changer (UPwdChg)
 *
 * @package    UPwdChg
 * @subpackage Resources_EN
 */
$sView = $oUPwdChg->getFormData('VIEW');
?>
<H1>Changement de mot de passe</H1>

<?php $sError = $oUPwdChg->getFormData('ERROR'); if(strlen($sError) > 0) { ?>
<DIV CLASS="error">
<H2>Erreur</H2>
<P STYLE="font-weight:bold;"><?php echo nl2br(htmlentities($sError)); ?></P>
</DIV>
<?php } ?>

<?php $sInfo = $oUPwdChg->getFormData('INFO'); if(strlen($sInfo) > 0) { ?>
<DIV CLASS="info">
<H2>Information</H2>
<P STYLE="font-weight:bold;"><?php echo nl2br(htmlentities($sInfo)); ?></P>
</DIV>
<?php } ?>

<?php if($sView == 'captcha') { ?>
<H2>Authentification</H2>
<DIV CLASS="text">
<P>Veuillez s'il-vous-plaît renseigner le texte du Captcha dans le formulaire ci-dessous.<BR/>
</DIV>
<DIV CLASS="form">
<?php echo $oUPwdChg->getFormHtml('captcha'); ?>
</DIV>

<?php } elseif($sView == 'password-change') { ?>
<H2>Changement de mot de passe</H2>
<DIV CLASS="text">
<P>Veuillez s'il-vous-plaît indiquer votre ancien et nouveau mot de passe dans le formulaire ci-dessous.<BR/>
<I>Note: tous les champs sont obligatoires.</I></P>
</DIV>
<DIV CLASS="form">
<?php echo $oUPwdChg->getFormHtml('password-change'); ?>
</DIV>

<?php } elseif($sView == 'password-change-confirm') { ?>
<H2>Succès!</H2>
<DIV CLASS="text">
<B>Le changement de votre mot de passe devrait être effectif dans les minutes qui suivent.</B></P>
<P><I>(veuillez s'il-vous-plaît vérifier votre messagerie électronique pour plus d'information)</I></P>
</DIV>

<?php } elseif($sView == 'password-nonce-request') { ?>
<H2>Demande de code PIN</H2>
<DIV CLASS="text">
<P>Veuillez s'il-vous-plaît indiquer votre nom d'utilisateur dans le formulaire ci-dessous.<BR/>
Vous recevrez ensuite un code PIN par un autre canal (SMS, courriel, ...).</P>
</DIV>
<DIV CLASS="form">
<?php echo $oUPwdChg->getFormHtml('password-nonce-request'); ?>
</DIV>

<?php } elseif($sView == 'password-reset') { ?>
<H2>Ré-initialisation du mot de passe</H2>
<DIV CLASS="text">
<P>Veuillez s'il-vous-plaît indiquer votre nom d'utilisateur, code PIN et nouveau mot de passe dans le formulaire ci-dessous.<BR/>
<I>Note: tous les champs sont obligatoires.</I></P>
</DIV>
<DIV CLASS="form">
<?php echo $oUPwdChg->getFormHtml('password-reset'); ?>
</DIV>

<?php } elseif($sView == 'password-reset-confirm') { ?>
<H2>Succès!</H2>
<DIV CLASS="text">
<B>La ré-initialisation de votre mot de passe devrait être effective dans les minutes qui suivent.</B></P>
<P><I>(veuillez s'il-vous-plaît vérifier votre messagerie électronique pour plus d'information)</I></P>
</DIV>

<?php } elseif($sView == 'password-policy') { ?>
<H2>Règles pour le mot de passe</H2>
<DIV CLASS="text">
<?php echo $oUPwdChg->getFormHtml('password-policy'); ?>
</DIV>
<?php } ?>

<?php if(count($oUPwdChg->getSupportedLocales()) > 1) { ?>
<HR/>
<DIV CLASS="form">
<?php echo $oUPwdChg->getFormHtml('locale'); ?>
</DIV>
<?php } ?>

<?php if($oUPwdChg->hasPasswordNonce()) { ?>
<DIV CLASS="form">
<?php echo $oUPwdChg->getFormHtml('reset'); ?>
</DIV>
<?php } ?>
