CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

create table if not exists customer_data (
    customerid text default null,
    -- productid text default null,
    name text default null,
    dob text default null,
    gender text default null,
    mobile text default null,
    phone text default null,
    email text default null,
    pan text default null,
    adhar text default null,
    address1 text default null,
    address2 text default null,
    address3 text default null,
    city text default null,
    state text default null,
    pincode text default null,
    country text default null,
    isadmin text default null,
    unique_identifier text default uuid_generate_v4(),
    updated_timestamp text default replace(cast(current_timestamp as text), '+05:30', '')
);

create table if not exists product_attributes (
    productid text default null,
    productname text default null,
    product_pricing text default null,
    payment_frequency text default null,
    unique_identifier text default uuid_generate_v4(),
    updated_timestamp text default replace(cast(current_timestamp as text), '+05:30', '')
);

create index if not exists customer_data_customer_id on customer_data(customerid);

create index if not exists customer_data_product_id on customer_data(productid);

create index if not exists customer_data_mobile on customer_data(mobile);

create index if not exists customer_data_phone on customer_data(phone);

DO $$ 
BEGIN
  BEGIN
    ALTER TABLE customer_data
    ADD CONSTRAINT unique_customer_id
    UNIQUE (customerid);
  EXCEPTION
    WHEN others THEN
      RAISE NOTICE 'An error occurred: %', SQLERRM;
  END;
END $$;

-- ALTER TABLE
--     product_customer_relation
-- ADD
--     FOREIGN KEY (customerid, productid) REFERENCES customer_data(customerid, productid);

DO $$ 
BEGIN
    IF NOT EXISTS (
        SELECT constraint_name
        FROM information_schema.table_constraints
        WHERE constraint_type = 'FOREIGN KEY' 
          AND table_name = 'product_customer_relation'
    ) THEN
        ALTER TABLE product_customer_relation
        ADD CONSTRAINT fk_customer_product
        FOREIGN KEY (customerid)
        REFERENCES customer_data(customerid);
    END IF;
END $$;



create table if not exists customer_password_details (
    customerid text default null,
    password text default null,
    unique_identifier text default uuid_generate_v4(),
    updated_timestamp text default replace(cast(current_timestamp as text), '+05:30', '')
);

