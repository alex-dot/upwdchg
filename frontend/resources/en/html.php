<!-- INDENTING (emacs/vi): -*- mode:html; tab-width:2; c-basic-offset:2; intent-tabs-mode:nil; -*- ex: set tabstop=2 expandtab: -->
<?php
/** Universal Password Changer (UPwdChg)
 *
 * @package    UPwdChg
 * @subpackage Resources_EN
 */
$sView = $oUPwdChg->getFormData('VIEW');
?>
<H1>Password Change</H1>

<?php $sError = $oUPwdChg->getFormData('ERROR'); if(strlen($sError) > 0) { ?>
<DIV CLASS="error">
<H2>Error</H2>
<P STYLE="font-weight:bold;"><?php echo nl2br(htmlentities($sError)); ?></P>
</DIV>
<?php } ?>

<?php if($sView == 'captcha') { ?>
<H2>Authentication</H2>
<DIV CLASS="text">
<P>Please provide the Captcha text in the form below.<BR/>
</DIV>
<DIV CLASS="form">
<?php echo $oUPwdChg->getFormHtml('captcha'); ?>
</DIV>

<?php } elseif($sView == 'password-change') { ?>
<H2>Password Change</H2>
<DIV CLASS="text">
<P>Please provide your old and new password in the form below.<BR/>
<I>Note: all fields are required.</I></P>
</DIV>
<DIV CLASS="form">
<?php echo $oUPwdChg->getFormHtml('password-change'); ?>
</DIV>

<?php } elseif($sView == 'password-change-confirm') { ?>
<H2>Success!</H2>
<DIV CLASS="text">
<B>Your password change should be effective within a few minutes.</B></P>
<P><I>(please check your e-mail inbox for further information)</I></P>
</DIV>

<?php } elseif($sView == 'password-nonce-request') { ?>
<H2>PIN Code Request</H2>
<DIV CLASS="text">
<P>Please provide your username in the form below.<BR/>
You will then receive a PIN code via another channel (SMS, e-mail, ...).</P>
</DIV>
<DIV CLASS="form">
<?php echo $oUPwdChg->getFormHtml('password-nonce-request'); ?>
</DIV>

<?php } elseif($sView == 'password-reset') { ?>
<H2>Password Reset</H2>
<DIV CLASS="text">
<P>Please provide your username, PIN code and new password in the form below.<BR/>
<I>Note: all fields are required.</I></P>
</DIV>
<DIV CLASS="form">
<?php echo $oUPwdChg->getFormHtml('password-reset'); ?>
</DIV>

<?php } elseif($sView == 'password-reset-confirm') { ?>
<H2>Success!</H2>
<DIV CLASS="text">
<B>Your password reset should be effective within a few minutes.</B></P>
<P><I>(please check your e-mail inbox for further information)</I></P>
</DIV>

<?php } elseif($sView == 'password-policy') { ?>
<H2>Password Policy</H2>
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
