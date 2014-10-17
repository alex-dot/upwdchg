<!-- INDENTING (emacs/vi): -*- mode:html; tab-width:2; c-basic-offset:2; intent-tabs-mode:nil; -*- ex: set tabstop=2 expandtab: -->
<?php
/** Universal Password Changer (UPwdChg)
 *
 * @package    UPwdChg
 * @subpackage Resources_EN
 */
$sView = $oUPwdChg->getFormData( 'VIEW' );
?>
<H1>Password Change</H1>

<?php $sError = $oUPwdChg->getFormData( 'ERROR' ); if( strlen( $sError ) > 0 ) { ?>
<DIV CLASS="error">
<H2>Error</H2>
<P STYLE="font-weight:bold;"><?php echo nl2br( htmlentities( $sError ) ); ?></P>
</DIV>
<?php } ?>

<?php if( $sView == 'default' ) { ?>
<H2>Credentials</H2>
<DIV CLASS="text">
<P>Please provide your old and new password in the form below.<BR/>
<I>Note: all fields are required.</I></P>
</DIV>
<DIV CLASS="form">
<?php echo $oUPwdChg->getFormHtml( 'credentials' ); ?>
</DIV>

<?php } elseif( $sView == 'policy' ) { ?>
<H2>Password Policy</H2>
<DIV CLASS="text">
<?php echo $oUPwdChg->getFormHtml( 'policy' ); ?>
</DIV>

<?php } elseif( $sView == 'confirm' ) { ?>
<H2>Success!</H2>
<DIV CLASS="text">
<B>Your password change should be effective within a few minutes.</B></P>
<P><I>(please check your e-mail inbox for further information)</I></P>
</DIV>
<?php } ?>

<?php if( count( $oUPwdChg->getSupportedLocales() ) > 1 ) { ?>
<HR/>
<DIV CLASS="form">
<?php echo $oUPwdChg->getFormHtml( 'locale' ); ?>
</DIV>
<?php } ?>
