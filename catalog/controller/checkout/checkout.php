<?php

/**
 * @copyright        2019 opencart.cn - All Rights Reserved
 * @link             http://www.guangdawangluo.com
 * @author:          Sam Chen <sam.chen@opencart.cn>
 * @created:         2017-07-31 11:48:04
 * @modified by:     Sam Chen <sam.chen@opencart.cn>
 * @modified:        2019-06-28 15:05:51
 */

class ControllerCheckoutCheckout extends Controller {
    private $ADDRESS_FIELDS = array(
        'firstname',
        'telephone',
        'company',
        'address_1',
        'address_2',
        'city',
        'postcode',
        'country_id',
        'zone_id',
        'city_id',
        'county_id',
        'custom_field'
    );

    public function __construct($registry) {
        parent::__construct($registry);
        $this->load->language('checkout/cart');
        $this->load->language('checkout/coupon');
        $this->load->language('checkout/checkout');
        $this->load->model('account/activity');
        $this->load->model('account/custom_field');
        $this->load->model('tool/upload');
        $this->load->model('account/address');
        $this->load->model('account/customer');
        $this->load->model('account/customer_group');
        $this->load->model('localisation/country');
        $this->load->model('localisation/zone');
        $this->load->model('checkout/checkout');
        $this->load->model('checkout/order');

        if ($this->isLogged()) {
            unset($this->session->data['guest']);
        }
    }

    public function index() {
        if (!$this->isValidCart()) {
            $this->log('Cart invalid');
            $this->response->redirect($this->url->link('checkout/cart'));
        }

        if (!$this->isLogged() && !config('config_checkout_guest')) {
            $this->session->data['redirect'] = $this->url->link('checkout/cart');
            $this->session->data['error'] = $this->language->get('warning_login');
            $this->response->redirect($this->url->link('account/login'));
        }

        $this->load->language('checkout/checkout');
        $this->document->setTitle($this->language->get('heading_title'));
        $this->document->addScript('catalog/view/javascript/jquery/datetimepicker/moment/moment.min.js');
        $this->document->addScript('catalog/view/javascript/jquery/datetimepicker/moment/moment-with-locales.min.js');
        $this->document->addScript('catalog/view/javascript/jquery/datetimepicker/bootstrap-datetimepicker.min.js');
        $this->document->addStyle('catalog/view/javascript/jquery/datetimepicker/bootstrap-datetimepicker.min.css');

        if (!$this->hasShipping()) {
            $this->log('Shipping not required.');
            unset($this->session->data['shipping_address']);
            unset($this->session->data['shipping_methods']);
            unset($this->session->data['shipping_method']);

            $this->fakeGuestAddressSession('payment');
        } else {
            if ($this->isLogged()) {
                if ($address_id = array_get($this->session->data, 'shipping_address.address_id')) {
                    $this->log("address_id: {$address_id}");
                    if ($address_info = $this->model_account_address->getAddress($address_id)) {
                        $this->syncAddressSession('shipping', $address_info);
                        $this->syncAddressSession('payment', $address_info);
                    } else {
                        $this->log("address_id: {$address_id} not found.");
                        unset($this->session->data['shipping_address']);
                        unset($this->session->data['payment_address']);
                        unset($this->session->data['shipping_methods']);
                        unset($this->session->data['payment_methods']);
                        unset($this->session->data['shipping_method']);
                        unset($this->session->data['payment_method']);
                    }
                }

                if (!array_get($this->session->data, 'shipping_address.address_id')) {
                    // User customer default address
                    if ($address_info = $this->model_account_address->getAddress($this->customer->getAddressId())) {
                        $this->syncAddressSession('shipping', $address_info);
                        $this->syncAddressSession('payment', $address_info);
                    } else {
                        $this->fakeGuestAddressSession('shipping');
                        $this->fakeGuestAddressSession('payment');
                    }
                }
            } else {
                if ($address = array_get($this->session->data, "guest.shipping_address")) {
                    $this->syncAddressSession('shipping', $address);
                } else {
                    // Use dummy address
                    $this->fakeGuestAddressSession('shipping');
                    $this->fakeGuestAddressSession('payment');
                }
            }
        }

        if ($this->hasShipping()) {
            $this->log($this->session->data['shipping_address']);
        }
        $this->log($this->session->data['payment_address']);

        $data['breadcrumbs'] = array();

        $data['breadcrumbs'][] = array(
            'text' => $this->language->get('text_home'),
            'href' => $this->url->link('common/home')
        );

        $data['breadcrumbs'][] = array(
            'text' => $this->language->get('text_cart'),
            'href' => $this->url->link('checkout/cart')
        );

        $data['breadcrumbs'][] = array(
            'text' => $this->language->get('heading_title'),
            'href' => $this->url->link('checkout/checkout')
        );

        if (isset($this->session->data['error'])) {
            $data['error_warning'] = $this->session->data['error'];
            unset($this->session->data['error']);
        } else {
            $data['error_warning'] = '';
        }

        $data['logged'] = $this->isLogged();
        $data['shipping_required'] = $this->hasShipping();

        if ($this->isLogged()) {
            if ($this->hasShipping()) {
                $data['shipping_address_section'] = $this->renderShippingAddressSection();
            }
        } else {
            $data['guest_address_section'] = $this->renderGuestAddressSection();
        }

        $data['shipping_method_section'] = $this->renderShippingMethodSection();
        $data['payment_method_section'] = $this->renderPaymentMethodSection();

        $data['cart_section'] = $this->renderCartSection();
        $data['comment_section'] = $this->renderCommentSection();
        $data['agree_section'] = $this->renderAgreeSection();

        $data['column_left'] = $this->load->controller('common/column_left');
        $data['column_right'] = $this->load->controller('common/column_right');
        $data['content_top'] = $this->load->controller('common/content_top');
        $data['content_bottom'] = $this->load->controller('common/content_bottom');
        $data['footer'] = $this->load->controller('common/footer');
        $data['header'] = $this->load->controller('common/header');

        $this->response->setOutput($this->load->view('checkout/checkout/checkout', $data));
    }

    // Update checkout
    public function update() {
        if ($this->request->server['REQUEST_METHOD'] != 'POST') {
            $this->response->redirect($this->url->link('checkout/cart'));
        }

        $this->log(__FUNCTION__);
        $this->log($this->request->post);

        $redirect = '';
        $error = array();

        if (!$this->isLogged() && !config('config_checkout_guest')) {
            $redirect = $this->url->link('account/login');
            $this->jsonOutput($error, $redirect);
            return;
        }

        if (!$this->isValidCart()) {
            $redirect = $this->url->link('checkout/cart');
            $this->jsonOutput($error, $redirect);
            return;
        }

        // Guest shipping address
        if (isset($this->request->post['guest_shipping_address'])) {
            $data = $this->request->post['guest_shipping_address'];

            $countryId = (int)array_get($data, 'country_id', config('config_country_id'));
            $zoneId = (int)array_get($data, 'zone_id', config('config_zone_id'));
            $cityId = (int)array_get($data, 'zone_id');
            $countyId = (int)array_get($data, 'county_id');

            $this->session->data['shipping_address']['country_id'] = $countryId;
            $this->session->data['shipping_address']['zone_id'] = $zoneId;
            $this->session->data['shipping_address']['city_id'] = $cityId;
            $this->session->data['shipping_address']['county_id'] = $countyId;

            $this->session->data['payment_address']['country_id'] = $countryId;
            $this->session->data['payment_address']['zone_id'] = $zoneId;
            $this->session->data['payment_address']['city_id'] = $cityId;
            $this->session->data['payment_address']['county_id'] = $countyId;

            $this->jsonOutput($error, $redirect, $this->reload());
            return;
        }

        // Shipping address form
        if ($this->getPostValue('shipping_country_id') || $this->getPostValue('shipping_zone_id')) {
            if (!$this->hasShipping()) {
                unset($this->session->data['shipping_address']);
                unset($this->session->data['shipping_methods']);
                unset($this->session->data['shipping_method']);
            } else {
                if (!$this->getPostValue('shipping_country_id')) {
                    $this->request->post['shipping_country_id'] = $this->model_checkout_checkout->getDefaultCountryId();
                }
                $this->session->data['shipping_address'] = [];
                foreach ($this->ADDRESS_FIELDS as $field) {
                    $this->session->data['shipping_address'][$field] = $this->getPostValue('shipping_' . $field, '');
                }
                $this->log($this->session->data['shipping_address']);
                $code = array_get($this->session->data, 'shipping_method.code');
                if (!$this->model_checkout_checkout->setShippingMethod($code)) {
                    $this->model_checkout_checkout->setShippingMethod();
                }
            }

            $this->jsonOutput($error, $redirect, $this->reload());
            return;
        }

        // Shipping address id
        if ($this->getPostValue('shipping_address_id')) {
            if (!$this->hasShipping()) {
                unset($this->session->data['shipping_address']);
                unset($this->session->data['shipping_methods']);
                unset($this->session->data['shipping_method']);
            } else {
                $address_info = $this->model_account_address->getAddress($this->getPostValue(('shipping_address_id')));
                $this->syncAddressSession('shipping', $address_info);
                $this->syncAddressSession('payment', $address_info);

                $code = array_get($this->session->data, 'shipping_method.code');
                if (!$this->model_checkout_checkout->setShippingMethod($code)) {
                    $this->model_checkout_checkout->setShippingMethod();
                }

                $code = array_get($this->session->data, 'payment_method.code');
                if (!$this->model_checkout_checkout->setPaymentMethod($code)) {
                    $this->model_checkout_checkout->setPaymentMethod();
                }
            }

            $this->jsonOutput($error, $redirect, $this->reload());
            return;
        }

        // Payment method
        if ($code = $this->getPostValue('payment_method')) {
            if (!array_get($this->session->data, 'payment_address')) {
                $redirect = $this->url->link('checkout/cart');
                $this->jsonOutput($error, $redirect);
                return;
            }

            if(!$this->model_checkout_checkout->setPaymentMethod($code)) {
                $this->session->data['error'] = $this->language->get('error_payment_unavailable');
                $redirect = $this->url->link('checkout/checkout');
            }

            $this->jsonOutput($error, $redirect, $this->reload());
            return;
        }

        // Shipping method
        if ($code = $this->getPostValue('shipping_method')) {
            if (!array_get($this->session->data, 'shipping_address')) {
                $redirect = $this->url->link('checkout/cart');
                $this->jsonOutput($error, $redirect);
                return;
            }

            if(!$this->model_checkout_checkout->setShippingMethod($code)) {
                $this->session->data['error'] = $this->language->get('error_shipping_unavailable');
                $redirect = $this->url->link('checkout/checkout');
            }

            $this->jsonOutput($error, $redirect, $this->reload());
            return;
        }
    }

    // Validate and submit order
    public function confirm() {
        $this->log(__FUNCTION__);
        $redirect = '';
        $error = array();

        if ($this->request->server['REQUEST_METHOD'] != 'POST') {
            $this->response->redirect($this->url->link('checkout/cart'));
        }

        if (!$this->isLogged() && !config('config_checkout_guest')) {
            $redirect = $this->url->link('account/login');
            $this->jsonOutput($error, $redirect);
            return;
        }

        if (!$this->isValidCart()) {
            $redirect = $this->url->link('checkout/cart');
            $this->jsonOutput($error, $redirect);
            return;
        }

        $this->log($this->request->post);

        $order_data = array();

        $order_data['payment_address'] = array();
        $order_data['shipping_address'] = array();

        // Shipping address
        if ($this->hasShipping()) {
            if ($this->isLogged()) {
                if ($this->getPostValue('shipping_address') == 'existing') {
                    $address_info = $this->model_account_address->getAddress($this->getPostValue(('shipping_address_id')));
                    if (!$address_info) { // Selected address not exists anymore
                        $this->session->data['warning_error'] = $this->language->get('error_address_not_exist');
                        $redirect = $this->url->link('checkout/checkout');
                        $this->jsonOutput($error, $redirect);
                        return;
                    }

                    $order_data['shipping_address'] = $address_info;
                    $order_data['payment_address'] = $address_info;
                    $this->syncAddressSession('shipping', $address_info);
                    $this->syncAddressSession('payment', $address_info);
                } else { // New address
                    if ($_error = $this->validateShippingAddress()) {
                        $error['shipping_address'] = $_error;
                    } else {
                        foreach ($this->ADDRESS_FIELDS as $field) {
                            $order_data['shipping_address'][$field] = $this->getPostValue('shipping_' . $field);
                        }

                        // Force payment address = shipping address
                        $order_data['payment_address'] = $order_data['shipping_address'];
                    }
                }
            } else {
                // Guest checkout
                if ($_error = $this->validateShippingAddress()) {
                    $error['shipping_address'] = $_error;
                }

                foreach ($this->ADDRESS_FIELDS as $field) {
                    $order_data['shipping_address'][$field] = $this->getPostValue('shipping_' . $field);
                }

                // Force payment address = shipping address
                $order_data['payment_address'] = $order_data['shipping_address'];
                $this->session->data['guest'] = $order_data['shipping_address'];
                $this->session->data['guest']['email'] = array_get($this->request->post, 'shipping_email');
            }
        } else {
            // None shipping required cart just need a dummy payment address
            unset($this->session->data['shipping_address']);
            $this->fakeGuestAddressSession('payment');
            $order_data['payment_address'] = $this->session->data['payment_address'];
        }

        // Payment method
        $payment_code = '';
        if (!$this->getPostValue('payment_method')) {
            $error['payment_method']['warning'] = $this->language->get('error_payment');
        } else {
            $code = $payment_code = $this->getPostValue('payment_method');
            if (!$this->model_checkout_checkout->setPaymentMethod($code)) {
                $error['payment_method']['warning'] = $this->language->get('error_payment_unavailable');
            } else {
                $order_data['payment_method'] = $code;
            }
        }
        // Shipping method
        if ($this->hasShipping()) {
            if (empty($error['shipping_address'])) {
                if (!$this->getPostValue('shipping_method')) {
                    $error['shipping_method']['warning'] = $this->language->get('error_shipping');
                } else {
                    $code = $this->getPostValue('shipping_method');
                    if (!$this->model_checkout_checkout->setShippingMethod($code)) {
                        $error['shipping_method']['warning'] = $this->language->get('error_shipping_unavailable');
                    } else {
                        $shipping = explode('.', $code);
                        $order_data['shipping_method'] = $this->session->data['shipping_methods'][$shipping[0]]['quote'][$shipping[1]];
                    }
                }
            }
        } else {
            unset($this->session->data['shipping_methods']);
            unset($this->session->data['shipping_method']);
        }

        // Comment
        $order_data['comment'] = $this->getPostValue('comment', '');

        // Terms & conditions agreement
        if ($this->config->get('config_checkout_id')) {
            $this->load->model('catalog/information');
            $information_info = $this->model_catalog_information->getInformation($this->config->get('config_checkout_id'));
            if ($information_info && !$this->getPostValue('terms')) {
                $error['agree']['terms'] = sprintf($this->language->get('error_agree'), $information_info['title']);
            }
        }

        if ($error) {
            $this->jsonOutput($error, $redirect);
            return;
        }

        // ALL set, update address session then submit the order
        $this->session->data['payment_address'] = $order_data['payment_address'];
        if ($this->hasShipping()) {
            $this->session->data['shipping_address'] = $order_data['shipping_address'];
        } else {
            unset($this->session->data['shipping_address']);
        }
        $this->session->data['comment'] = $order_data['comment'];

        // Add new addresses to db for logged in customer
        if ($this->isLogged()) {
            foreach (['shipping'] as $type) {
                if ($type == 'shipping' && !$this->hasShipping()) {
                    continue;
                }

                if ($this->getPostValue($type . '_address') != 'existing') {
                    // Make the address as default is the customer does not have an address yet
                    if (!$this->customer->getAddressId()) {
                        $order_data[$type . '_address']['default'] = true;
                    }
                    $address_id = $this->model_account_address->addAddress($this->customer->getId(), $order_data[$type . '_address']);
                    $address_info = $this->model_account_address->getAddress($address_id);
                    $this->syncAddressSession($type, $address_info);
                }
            }
        }

        $order_id = $this->model_checkout_checkout->createOrder();

        // Change order status to Unpaid
        if ($order_data['payment_method'] == 'cod') {
            $this->model_checkout_order->addOrderHistory($order_id, $this->config->get('payment_cod_order_status_id'));
        }

        if ($payment_code == 'pp_express') {
            $pp_express_confirm = \Paypal\Paypal::getSingleton()->confirmExpress();
            if (isset($pp_express_confirm['redirect'])) {
                $redirect = $pp_express_confirm['redirect'];
            }
            if (isset($pp_express_confirm['error'])) {
                $error['pp'] = $pp_express_confirm['error'];
            }
        }

        $this->jsonOutput($error, $redirect);
        return;
    }

    public function reload() {
        $data['payment_method_section'] = $this->renderPaymentMethodSection();
        $data['shipping_method_section'] = $this->renderShippingMethodSection();
        $data['cart_section'] = $this->renderCartSection();
        return $data;
    }

    // Payment connect page when order created
    public function connect() {
        $this->log(__FUNCTION__);
        if (!isset($this->session->data['order_id']) || (int)$this->session->data['order_id'] <= 0) {
            $this->response->redirect($this->url->link('common/home'));
        }

        $data['order_id'] = $order_id = (int)$this->session->data['order_id'];
        $order = $this->model_checkout_order->getOrder($order_id);
        if (!$order) {
            $this->response->redirect($this->url->link('common/home'));
        }

        // Redirect cod order to checkout/success page
        if ($order['payment_code'] == 'cod') {
            $this->response->redirect($this->url->link('checkout/success'));
        }

        // Check if order is unpaid
        if ($order['order_status_id'] != 0) {
            $this->response->redirect($this->url->link('account/order/info', 'order_id=' . $order['order_id']));
        }

        $this->load->language('checkout/connect');

        $this->document->setTitle($this->language->get('heading_title'));
        $data['heading_title'] = $this->language->get('heading_title');

        $data['text_success'] = $this->language->get('text_success');
        $data['column_order_id'] = $this->language->get('column_order_id');
        $data['column_total'] = $this->language->get('column_total');
        $data['column_shipping_method'] = $this->language->get('column_shipping_method');
        $data['column_payment_method'] = $this->language->get('column_payment_method');
        $data['button_view'] = $this->language->get('button_view');

        $data['total'] = $this->currency->format($order['total'], $order['currency_code'], $order['currency_value']);

        $data['shipping_method'] = $order['shipping_method'] ?: false;
        $data['payment_method'] = $order['payment_method'];

        $payment_code = $order['payment_code'];
        if ($payment_code == 'cod') {
            $data['payment_view'] = false;
        } else {
            $data['payment_view'] = $this->load->controller("extension/payment/{$payment_code}");
        }

        $data['href'] = $this->url->link('account/order/info', 'order_id=' . $order['order_id']);

        $data['column_left'] = $this->load->controller('common/column_left');
        $data['column_right'] = $this->load->controller('common/column_right');
        $data['content_top'] = $this->load->controller('common/content_top');
        $data['content_bottom'] = $this->load->controller('common/content_bottom');
        $data['footer'] = $this->load->controller('common/footer');
        $data['header'] = $this->load->controller('common/header');

        $this->response->setOutput($this->load->view('checkout/connect', $data));
    }

    // Helpers
    private function isLogged() {
        return $this->customer->isLogged();
    }

    private function hasShipping() {
        return $this->cart->hasShipping();
    }

    private function isValidCart() {
        // Validate cart has products and has stock.
        if ((!$this->cart->hasProducts() && empty($this->session->data['vouchers']) && empty($this->session->data['recharges'])) || (!$this->cart->hasStock() && !$this->config->get('config_stock_checkout'))) {
            return false;
        }

        // Validate minimum quantity requirements.
        $products = $this->cart->getProducts();

        foreach ($products as $product) {
            $product_total = 0;

            foreach ($products as $product_2) {
                if ($product_2['product_id'] == $product['product_id']) {
                    $product_total += $product_2['quantity'];
                }
            }

            if ($product['minimum'] > $product_total) {
                return false;
            }
        }

        return true;
    }

    private function getPostValue($key, $default = null) {
        return array_get($this->request->post, $key, $default);
    }

    private function jsonOutput($error = array(), $redirect = '', $html = null) {
        $json = array(
            'error' => $error ? (object)$error : null,
            'redirect' => $redirect,
            'html' => $html,
        );
        $this->response->addHeader('Content-Type: application/json');
        $this->response->setOutput(json_encode($json));
    }

    // Views
    public function renderGuestAddressSection()
    {
        $data['login'] = $this->url->link('account/login');
        $data['register'] = $this->url->link('account/register');

        $this->load->model('localisation/country');
        $data['countries'] = $this->model_localisation_country->getCountries();

        // Custom Fields
        $this->load->model('account/custom_field');
        $custom_fields = $this->model_account_custom_field->getCustomFields($this->config->get('config_customer_group_id'));
        foreach ($custom_fields as $custom_field) {
            if ($custom_field['location'] == 'address') {
                $data['custom_fields'][] = $custom_field;
            }
        }

        $this->document->addScript('catalog/view/javascript/jquery/datetimepicker/moment/moment.min.js');
        $this->document->addScript('catalog/view/javascript/jquery/datetimepicker/moment/moment-with-locales.min.js');
        $this->document->addScript('catalog/view/javascript/jquery/datetimepicker/bootstrap-datetimepicker.min.js');
        $this->document->addStyle('catalog/view/javascript/jquery/datetimepicker/bootstrap-datetimepicker.min.css');

        // 默认值
        $data['config_country_id'] = config('config_country_id');
        $data['config_zone_id'] = config('config_zone_id');

        // 省市县是否需要显示国家选择？
        $data['config_select_country'] = config('config_select_country');

        return $this->load->view("checkout/checkout/_guest_address", $data);
    }

    private function renderShippingAddressSection() {
        $this->log(__FUNCTION__);
        $data['logged'] = $this->isLogged();

        if (isset($this->session->data['shipping_address']['address_id'])) {
            $data['address_id'] = $this->session->data['shipping_address']['address_id'];
        } else {
            $data['address_id'] = $this->customer->getAddressId();
        }

        $this->load->model('account/address');

        $data['addresses'] = $this->model_account_address->getAddresses();

        if (isset($this->session->data['shipping_address']['postcode'])) {
            $data['postcode'] = $this->session->data['shipping_address']['postcode'];
        } else {
            $data['postcode'] = '';
        }

        if (isset($this->session->data['shipping_address']['country_id'])) {
            $data['country_id'] = $this->session->data['shipping_address']['country_id'];
        } else {
            $data['country_id'] = $this->config->get('config_country_id');
        }

        if (isset($this->session->data['shipping_address']['zone_id'])) {
            $data['zone_id'] = $this->session->data['shipping_address']['zone_id'];
        } else {
            $data['zone_id'] = '';
        }

        $this->load->model('localisation/country');

        $data['countries'] = $this->model_localisation_country->getCountries();

        // Custom Fields
        $this->load->model('account/custom_field');

        $data['custom_fields'] = $this->model_account_custom_field->getCustomFields($this->config->get('config_customer_group_id'));

        if (isset($this->session->data['shipping_address']['custom_field'])) {
            $data['shipping_address_custom_field'] = $this->session->data['shipping_address']['custom_field'];
        } else {
            $data['shipping_address_custom_field'] = array();
        }

        // 省市县是否需要显示国家选择？
        $data['config_select_country'] = config('config_select_country');

        return $this->load->view('checkout/checkout/_shipping_address', $data);
    }

    private function renderPaymentMethodSection() {
        $this->log(__FUNCTION__);
        if (isset($this->session->data['payment_address'])) {
            $this->model_checkout_checkout->getPaymentMethods();
        }

        if (empty($this->session->data['payment_methods'])) {
            $data['error_warning'] = sprintf($this->language->get('error_no_payment'), $this->url->link('information/contact'));
        } else {
            $data['error_warning'] = '';
        }

        if (isset($this->session->data['payment_methods'])) {
            $data['payment_methods'] = $this->session->data['payment_methods'];
        } else {
            $data['payment_methods'] = array();
        }

        if (isset($this->session->data['payment_method']['code'])) {
            $data['code'] = $this->session->data['payment_method']['code'];
        } else {
            $data['code'] = '';
        }

        if (isset($this->session->data['comment'])) {
            $data['comment'] = $this->session->data['comment'];
        } else {
            $data['comment'] = '';
        }

        return $this->load->view('checkout/checkout/_payment_method', $data);
    }

    private function renderShippingMethodSection() {
        $this->log(__FUNCTION__);
        $data['shipping'] = $this->hasShipping();

        if ($this->hasShipping()) {
            if (isset($this->session->data['shipping_address'])) {
                // Shipping Methods
                $this->model_checkout_checkout->getShippingMethods();
            }

            if (empty($this->session->data['shipping_methods'])) {
                $data['error_warning'] = sprintf($this->language->get('error_no_shipping'), $this->url->link('information/contact'));
            } else {
                $data['error_warning'] = '';
            }

            if (isset($this->session->data['shipping_methods'])) {
                $data['shipping_methods'] = $this->session->data['shipping_methods'];
            } else {
                $data['shipping_methods'] = array();
            }

            if (isset($this->session->data['shipping_method']['code'])) {
                $data['code'] = $this->session->data['shipping_method']['code'];
            } else {
                $data['code'] = '';
            }
        } else {
            $data['text_shipping_not_required'] = $this->language->get('text_shipping_not_required');
        }

        return $this->load->view('checkout/checkout/_shipping_method', $data);
    }

    private function renderCommentSection() {
        $this->log(__FUNCTION__);
        if (isset($this->session->data['comment'])) {
            $data['comment'] = $this->session->data['comment'];
        } else {
            $data['comment'] = '';
        }

        return $this->load->view('checkout/checkout/_comment', $data);
    }

    private function renderCartSection() {
        $this->log(__FUNCTION__);
        $data['products'] = $this->getProducts();
        $data['vouchers'] = $this->getVouchers();
        $data['totals'] = $this->getTotals();

        return $this->load->view('checkout/checkout/_confirm', $data);
    }

    private function renderAgreeSection() {
        $this->log(__FUNCTION__);

        // Payment method
        if ($this->config->get('config_checkout_id')) {
            $this->load->model('catalog/information');
            $information_info = $this->model_catalog_information->getInformation($this->config->get('config_checkout_id'));
            if ($information_info) {
                $data['text_payment_method'] = sprintf($this->language->get('text_agree'), $this->url->link('information/information/agree', 'information_id=' . $this->config->get('config_checkout_id')), $information_info['title'], $information_info['title']);
            } else {
                $data['text_payment_method'] = '';
            }
        } else {
            $data['text_payment_method'] = '';
        }

        $data['terms'] = (int)array_get($this->session->data, 'checkout_terms');

        return $this->load->view('checkout/checkout/_agree', $data);
    }

    // Private
    private function getProducts() {
        $this->load->model('tool/image');
        $products = array();

        foreach ($this->cart->getProducts() as $product) {
            $image = $this->model_tool_image->resize($product['image'] ?: 'placeholder.png', $this->config->get('theme_' . $this->config->get('config_theme') . '_image_cart_width'), $this->config->get('theme_' . $this->config->get('config_theme') . '_image_cart_height'));

            $option_data = array();
            foreach ($product['option'] as $option) {
                if ($option['type'] != 'file') {
                    $value = $option['value'];
                } else {
                    $upload_info = $this->model_tool_upload->getUploadByCode($option['value']);
                    if ($upload_info) {
                        $value = $upload_info['name'];
                    } else {
                        $value = '';
                    }
                }

                $option_data[] = array(
                    'name'  => $option['name'],
                    'value' => (utf8_strlen($value) > 20 ? utf8_substr($value, 0, 20) . '..' : $value)
                );
            }


            $products[] = array(
                'cart_id'    => $product['cart_id'],
                'product_id' => $product['product_id'],
                'image'      => $image,
                'name'       => $product['name'],
                'model'      => $product['model'],
                'option'     => $option_data,
                'quantity'   => $product['quantity'],
                'subtract'   => $product['subtract'],
                'price'      => $this->currency->format($this->tax->calculate($product['price'], $product['tax_class_id'], $this->config->get('config_tax')), $this->session->data['currency']),
                'total'      => $this->currency->format($this->tax->calculate($product['price'], $product['tax_class_id'], $this->config->get('config_tax')) * $product['quantity'], $this->session->data['currency']),
                'href'       => $this->url->link('product/product', 'product_id=' . $product['product_id'])
            );
        }

        return $products;
    }

    private function getVouchers() {
        $vouchers = array();

        if (empty($this->session->data['vouchers'])) {
            return $vouchers;
        }

        foreach ($this->session->data['vouchers'] as $voucher) {
            $vouchers[] = array(
                'description' => $voucher['description'],
                'amount'      => $this->currency->format($voucher['amount'], $this->session->data['currency'])
            );
        }

        return $vouchers;
    }

    private function getTotals() {
        $totals = array();
        $taxes = $this->cart->getTaxes();
        $total = 0;

        // Because __call can not keep var references so we put them into an array.
        $total_data = array(
            'totals' => &$totals,
            'taxes'  => &$taxes,
            'total'  => &$total
        );

        $this->load->model('setting/extension');
        $sort_order = array();
        $results = $this->model_setting_extension->getExtensions('total');
        foreach ($results as $key => $value) {
            $sort_order[$key] = $this->config->get('total_' . $value['code'] . '_sort_order');
        }

        array_multisort($sort_order, SORT_ASC, $results);
        foreach ($results as $result) {
            if ($this->config->get('total_' . $result['code'] . '_status')) {
                $this->load->model('extension/total/' . $result['code']);

                // We have to put the totals in an array so that they pass by reference.
                $this->{'model_extension_total_' . $result['code']}->getTotal($total_data);
            }
        }

        $sort_order = array();
        foreach ($totals as $key => $value) {
            $sort_order[$key] = $value['sort_order'];
        }
        array_multisort($sort_order, SORT_ASC, $totals);

        $results = array();

        foreach ($totals as $total) {
            $results[] = array(
                'title' => $total['title'],
                'text'  => $this->currency->format($total['value'], $this->session->data['currency'])
            );
        }

        return $results;
    }

    // Address
    private function syncAddressSession($type, $address_info) {
        if (!in_array($type, ['payment', 'shipping'])) {
            return false;
        }

        if ($type == 'shipping' && !$this->hasShipping()) {
            unset($this->session->data['shipping_address']);
            unset($this->session->data['shipping_methods']);
            unset($this->session->data['shipping_method']);
            return false;
        }

        $this->session->data["{$type}_address"] = $address_info;

        if ($type == 'payment') {
            if ($code = array_get($this->session->data, 'payment_method.code')) {
                if (!$this->model_checkout_checkout->setPaymentMethod($code)) {
                    $this->model_checkout_checkout->setPaymentMethod();
                }
            } else {
                $this->model_checkout_checkout->setPaymentMethod();
            }
        }

        if ($type == 'shipping') {
            if ($code = array_get($this->session->data, 'shipping_method.code')) {
                if (!$this->model_checkout_checkout->setShippingMethod($code)) {
                    $this->model_checkout_checkout->setShippingMethod();
                }
            } else {
                $this->model_checkout_checkout->setShippingMethod();
            }
        }
    }

    private function fakeGuestAddressSession($type) {
        if (!in_array($type, ["payment", "shipping"])) {
            return;
        }

        $this->session->data[$type . '_address'] = array();
        foreach ($this->ADDRESS_FIELDS as $field) {
            $this->session->data[$type . '_address'][$field] = '';
        }

        $this->session->data[$type . '_address']['country_id'] = $this->model_checkout_checkout->getDefaultCountryId();
        $this->session->data[$type . '_address']['zone_id'] = $this->model_checkout_checkout->getDefaultZoneId();

        $this->syncAddressSession($type, $this->session->data[$type . '_address']);
    }

    private function validateShippingAddress() {
        $error = array();

        if ((utf8_strlen(trim($this->request->post['shipping_firstname'])) < 1) || (utf8_strlen(trim($this->request->post['shipping_firstname'])) > 32)) {
            $error['firstname'] = $this->language->get('error_firstname');
        }

        // 游客需要填写邮箱地址
        if (!$this->customer->isLogged()) {
            $email = trim((string)array_get($this->request->post, 'shipping_email'));
            if ((utf8_strlen($email) > 96) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
                $error['email'] = t('error_email');
            }
        }

        if ((utf8_strlen(trim($this->request->post['shipping_telephone'])) < 1) || (utf8_strlen(trim($this->request->post['shipping_telephone'])) > 32)) {
            $error['telephone'] = $this->language->get('error_telephone');
        }

        if ((utf8_strlen(trim($this->request->post['shipping_address_1'])) < 3) || (utf8_strlen(trim($this->request->post['shipping_address_1'])) > 128)) {
            $error['address_1'] = $this->language->get('error_address_1');
        }

        $country_id = (int)array_get($this->request->post, 'shipping_country_id');
        if ($country_id < 1) {
            $error['country_id'] = $this->language->get('error_country');
        } else {
            $country_info = $this->model_localisation_country->getCountry($country_id);
            if ($country_info && $country_info['postcode_required'] && (utf8_strlen(trim($this->request->post['shipping_postcode'])) < 2 || utf8_strlen(trim($this->request->post['shipping_postcode'])) > 10)) {
                $error['postcode'] = $this->language->get('error_postcode');
            }
        }

        $zone_id = (int)array_get($this->request->post, 'shipping_zone_id');
        if ($zone_id < 1) {
            $error['zone_id'] = $this->language->get('error_zone');
        }

        $city_id = (int)array_get($this->request->post, 'shipping_city_id');
        if ($zone_id > 0) {
            $this->load->model('localisation/city');
            $cities = $this->model_localisation_city->getCitiesByZoneId($zone_id, true);
            // 当前 zone 下有 city, 但 city 没有选择
            if (!empty($cities)) {
                if ($city_id < 1) {
                    $error['city_id'] =  t('error_city');
                } else {
                    $this->request->post['city'] = '';
                }
            } else { // 当前 zone 下没有 city
                $city_id = 0;
                $this->request->post['city_id'] = 0;
                $this->request->post['county_id'] = 0;
            }
        }

        $county_id = (int)array_get($this->request->post, 'shipping_county_id');
        if ($city_id > 0) {
            $this->load->model('localisation/city');
            $counties = $this->model_localisation_city->getCitiesByZoneId($city_id, false);
            // 当前 city 下有 county, 但 county 没有选择
            if (!empty($counties)) {
                if ($county_id < 1) {
                    $error['county_id'] =  t('error_county');
                }
            }
        }

        if (!$this->isLogged()) {
            if (isset($this->request->post['customer_group_id']) && is_array($this->config->get('config_customer_group_display')) && in_array($this->request->post['customer_group_id'], $this->config->get('config_customer_group_display'))) {
                $customer_group_id = $this->request->post['customer_group_id'];
            } else {
                $customer_group_id = $this->config->get('config_customer_group_id');
            }
        } else {
            $customer_group_id = $this->config->get('config_customer_group_id');
        }

        // Custom field validation
        $this->load->model('account/custom_field');
        $custom_fields = $this->model_account_custom_field->getCustomFields($customer_group_id);
        foreach ($custom_fields as $custom_field) {
            if (($custom_field['location'] == 'address') && $custom_field['required'] && empty($this->request->post['shipping_custom_field'][$custom_field['custom_field_id']])) {
                $error['custom_field' . $custom_field['custom_field_id']] = sprintf($this->language->get('error_custom_field'), $custom_field['name']);
            } elseif (($custom_field['location'] == 'address') && ($custom_field['type'] == 'text') && !empty($custom_field['validation']) && !filter_var($this->request->post['shipping_custom_field'][$custom_field['custom_field_id']], FILTER_VALIDATE_REGEXP, array('options' => array('regexp' => $custom_field['validation'])))) {
                $error['custom_field' . $custom_field['custom_field_id']] = sprintf($this->language->get('error_custom_field'), $custom_field['name']);
            }
        }

        return $error;
    }

    private function log($data = null) {
        if ($data) {
            $this->model_checkout_checkout->log($data);
        }
    }

    // Original
    public function country() {
        $json = array();

        $this->load->model('localisation/country');

        $country_info = $this->model_localisation_country->getCountry($this->request->get['country_id']);

        if ($country_info) {
            $this->load->model('localisation/zone');

            $json = array(
                'country_id'        => $country_info['country_id'],
                'name'              => $country_info['name'],
                'iso_code_2'        => $country_info['iso_code_2'],
                'iso_code_3'        => $country_info['iso_code_3'],
                'address_format'    => $country_info['address_format'],
                'postcode_required' => $country_info['postcode_required'],
                'zone'              => $this->model_localisation_zone->getZonesByCountryId($this->request->get['country_id']),
                'status'            => $country_info['status']
            );
        }

        $this->response->addHeader('Content-Type: application/json');
        $this->response->setOutput(json_encode($json));
    }

    public function customfield() {
        $json = array();

        $this->load->model('account/custom_field');

        // Customer Group
        if (isset($this->request->get['customer_group_id']) && is_array($this->config->get('config_customer_group_display')) && in_array($this->request->get['customer_group_id'], $this->config->get('config_customer_group_display'))) {
            $customer_group_id = $this->request->get['customer_group_id'];
        } else {
            $customer_group_id = $this->config->get('config_customer_group_id');
        }

        $custom_fields = $this->model_account_custom_field->getCustomFields($customer_group_id);

        foreach ($custom_fields as $custom_field) {
            $json[] = array(
                'custom_field_id' => $custom_field['custom_field_id'],
                'required'        => $custom_field['required']
            );
        }

        $this->response->addHeader('Content-Type: application/json');
        $this->response->setOutput(json_encode($json));
    }
}
