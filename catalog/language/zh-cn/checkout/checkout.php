<?php
/**
 * description
 *
 * @copyright        2016 opencart.cn - All Rights Reserved
 * @link             http://www.guangdawangluo.com
 * @author           Sam Chen <sam.chen@opencart.cn>
 * @created          2016-10-23 11:22:04
 * @modified         2017-08-07 16:11:48
 */

// Heading
$_['heading_title']                  = '结账';

// Text
$_['text_cart']                      = '购物车';
$_['text_checkout_option']           = '结账选项';
$_['text_checkout_account']          = '账号详细';
$_['text_checkout_payment_address']  = '账单地址';
$_['text_checkout_shipping_address'] = '配送地址';
$_['text_checkout_shipping_method']  = '配送方式';
$_['text_checkout_payment_method']   = '支付方式';
$_['text_checkout_confirm']          = '确认订单';
$_['text_checkout_cart']             = '购物车';
$_['text_modify']                    = '更新';
$_['text_new_customer']              = '新客户';
$_['text_returning_customer']        = '注册用户';
$_['text_checkout']                  = '结账选项';
$_['text_i_am_returning_customer']   = '我已注册账户';
$_['text_register']                  = '注册账户';
$_['text_guest']                     = '直接结账';
$_['text_register_account']          = '注册一个账户以便您更快捷地购物，查看订单状态，查看采购的历史记录，和更多的管理项目。';
$_['text_forgotten']                 = '忘记密码';
$_['text_your_details']              = '我的个人信息';
$_['text_your_address']              = '我的地址';
$_['text_your_password']             = '我的密码';
$_['text_agree']                     = '我已阅读并同意 <a href="%s"class="agree"> <b>%s</b></a>';
$_['text_address_new']               = '添加新地址';
$_['text_address_existing']          = '使用现有地址';
$_['text_shipping_method']           = '请选择配送方式。';
$_['text_payment_method']            = '请选择支付方式。';
$_['text_comments']                  = '订单留言';
$_['text_recurring']                 = '分期项目';
$_['text_payment_recurring']         = '分期付款';
$_['text_trial_description']         = '%s 每次 %d %s(s) 为 %d 付款(s) 然后';
$_['text_payment_description']       = '%s 每次 %d %s(s) 为 %d 付款(s)';
$_['text_payment_until_canceled_description'] = '%s 每 %d %s(s) 直到取消';
$_['text_day']                       = '天';
$_['text_week']                      = '周';
$_['text_semi_month']                = '半月';
$_['text_month']                     = '月';
$_['text_year']                      = '年';
$_['text_shipping_not_required']     = '购物车商品不需要配送';

// Column
$_['column_name']                    = '商品名称';
$_['column_model']                   = '型号';
$_['column_quantity']                = '数量';
$_['column_price']                   = '单价';
$_['column_total']                   = '合计';

// Entry
$_['entry_email_address']            = '邮件地址';
$_['entry_email']                    = 'Email';
$_['entry_password']                 = '密码';
$_['entry_confirm']                  = '确认密码';
$_['entry_firstname']                 = '您的姓名';
$_['entry_telephone']                = '联系电话';
$_['entry_fax']                      = '传真';
$_['entry_address']                  = '选择地址';
$_['entry_company']                  = '公司名称';
$_['entry_customer_group']           = '客户组';
$_['entry_address_1']                = '详细地址';
$_['entry_address_2']                = '地址 2';
$_['entry_postcode']                 = '邮政编码';
$_['entry_county']                   = '区县';
$_['entry_city']                     = '城市';
$_['entry_country']                  = '国家';
$_['entry_zone']                     = '省份';
$_['entry_newsletter']               = '同意订阅 %s。';
$_['entry_shipping']                 = '我的配送地址和运单地址相同。';

// Error
$_['error_warning']                  = '在结算时出现了问题！如果此问题继续存在请使用其它支付方式或 <a href="%s">联系我们</a>。';
$_['error_login']                    = '错误：邮件地址或是密码不正确。';
$_['error_attempts']                 = '错误: 您的账户已经超过最大尝试登录次数，请在一小时后再试。';
$_['error_approved']                 = '提示：您的账户需要通过审核，才可以登录。';
$_['error_exists']                   = '错误：该邮箱地址已被注册、请换一个电子邮箱！';
$_['error_firstname']                 = '姓名必须在 1 至 32 字符之间！';
$_['error_email']                    = '无效的邮箱地址！';
$_['error_telephone']                = '联系电话必须在 2 至 32 字符之间！';
$_['error_password']                 = '密码必须在 2 至 20 字符之间！';
$_['error_confirm']                  = '确认密码与输入密码不一致！';
$_['error_address_1']                = '详细地址必须在 2 至 128 字符之间！';
$_['error_county']                   = '请选择区县！';
$_['error_city']                     = '请选择城市！';
$_['error_postcode']                 = '邮编必须在 2 至 10 字符之间！';
$_['error_country']                  = '请选择国家！';
$_['error_zone']                     = '请选择省份！';
$_['error_agree']                    = '错误：您未同意条款 %s！';
$_['error_address']                  = '提示：请选择一个地址！';
$_['error_address_not_exist']        = '您选择的地址不存在，请重新选择一个地址！';
$_['error_shipping']                 = '提示：请选择一个配送方式！';
$_['error_no_shipping']              = '无可用配送方式。 请<a href="%s">联系我们</a> 以获取帮助！';
$_['error_payment']                  = '提示：请选择一个支付方式！';
$_['error_no_payment']               = '错误：无可用支付方式。 请<a href="%s">联系我们</a> 以获取帮助！';
$_['error_payment_unavailable']      = '抱歉，您选择的支付方式不可用，请尝试其它支付方式！';
$_['error_shipping_unavailable']     = '抱歉，您选择的配送方式不可用，请尝试其它配送方式！';
$_['error_custom_field']             = '%s 必填！';
$_['error_recharge_cannot_checkout_with_product']  = '提示：充值项目必须单独结账，不能与其他同时结账！';

// Warning
$_['warning_login']                  = '您还没有登录，登录后才能结账哦。';
